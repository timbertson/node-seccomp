// #define BUILDING_NODE_EXTENSION
#include <node.h>


/******************** limit_syscalls.c *************/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <seccomp.h>

// Created by Vitaly "_Vi" Shukela; 2013; License=MIT

// missing from seccomp.h? or is it private?
extern "C" {
  int seccomp_syscall_resolve_name(char*);
}

/* Workaround missing va_list version of seccomp_rule_add */
static int seccomp_rule_add_hack(scmp_filter_ctx ctx, uint32_t action, 
    int syscall, unsigned int arg_cnt, struct scmp_arg_cmp *args) {
        if(arg_cnt==0) return seccomp_rule_add(ctx, action, syscall, arg_cnt);
        if(arg_cnt==1) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0]);
        if(arg_cnt==2) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0], args[1]);
        if(arg_cnt==3) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0], args[1], args[2]);
        if(arg_cnt==4) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0], args[1], args[2], args[3]);
        if(arg_cnt==5) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0], args[1], args[2], args[3], args[4]);
        if(arg_cnt==6) return seccomp_rule_add(ctx, action, syscall, arg_cnt,
            args[0], args[1], args[2], args[3], args[4], args[5]);
    return -1;
}

/****************************************************/

#define ERR(reason) { ThrowException(Exception::Error(String::New(reason))); return scope.Close(Undefined());};
#define ERR_INT(reason, i) { ThrowException(Exception::Error(String::Concat(String::New(reason), Integer::New(i)->ToString()))); return scope.Close(Undefined());};
#define ERR_CONCAT(a,b) { ThrowException(Exception::Error(String::Concat(String::New(a), String::New(b)))); return scope.Close(Undefined());};
#define ERR_STR(reason, str) { ThrowException(Exception::Error(String::Concat(String::New(reason), str))); return scope.Close(Undefined());};
#define ERR_CUSTOM(str) { ThrowException(Exception::Error(str)); return scope.Close(Undefined());};
#define EXTEND_BUF(size) { \
    if (bufsize < size+1) { \
      bufsize = size*2 + 1; \
      buf = (char*)realloc(buf, bufsize * sizeof(char)); \
      if(buf == NULL) ERR("Out of memory"); \
    } \
  }


#define STRBUF(str) { \
  int _len = arg->Utf8Length(); \
  EXTEND_BUF(_len); \
  arg->WriteUtf8(buf, bufsize); \
}

using namespace v8;

Handle<Value> Seccomp(const Arguments& args) {
  HandleScope scope;

  if (args.Length() != 1) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }

  // Local<Object> opts = Object::Cast(args[0]);
  if (!args[0]->IsObject()) {
    ThrowException(Exception::TypeError(String::New("Argument must be an object")));
    return scope.Close(Undefined());
  }

  Handle<Object> opts = Handle<Object>::Cast(args[0]);
  Handle<Array> allowed_calls = Handle<Array>::Cast(opts->Get(String::New("allowed_calls")));
  Handle<Array> default_action_opt = Handle<Array>::Cast(opts->Get(String::New("default_action")));

  // ECHRNG, just to provide more or less noticable message when we block a syscall
  uint32_t default_action = SCMP_ACT_ERRNO(44);

  char* buf;
  int bufsize = 4;
  buf = (char*)malloc(sizeof(char) * bufsize);
  if(buf == NULL) ERR("Out of memory");
  
  if(!default_action_opt->IsUndefined()) {
      if(default_action_opt->IsString()) {
        if(default_action_opt->Equals(String::New("allow"))) {
          // printf("default: allow\n");
          default_action = SCMP_ACT_ALLOW;
        } else if(default_action_opt->Equals(String::New("kill"))) {
          // printf("default: kill\n");
          default_action = SCMP_ACT_KILL;
        } else {
          ERR_STR("Unknown action. Expected 'allow' or 'write', got: ", Handle<String>::Cast(default_action_opt));
        }
      } else if (default_action_opt->IsInt32()) {
        int errno_ = Handle<Int32>::Cast(default_action_opt)->Value();
        // printf("default: ERRNO %d\n", errno_);
        default_action = SCMP_ACT_ERRNO(errno_);
      } else {
        ERR("default_action must be a string or int");
      }
  }
  
  scmp_filter_ctx ctx = seccomp_init(default_action);
  if (!ctx) {
      ERR("seccomp_init failed");
  }

  // seccomp_export_pfc(ctx, 1);
  
  int i;
  
  
  int num_syscalls = allowed_calls->Length();
  int ret; // error codes from C calls

  for (i=0; i<num_syscalls; ++i) {
      // printf("array length = %d\n", num_syscalls);
      Handle<Value> arrayElement = allowed_calls->Get(i);
      // printf("got elem\n");
      if(!arrayElement->IsString()) {
        ERR("expected string");
      }
 
      Handle<String> arg = Handle<String>::Cast(arrayElement);
      if(arg.IsEmpty()) {
        ERR("what?");
      }

      STRBUF(arg);
      // printf("buf: %s\n", buf);

      // -- below follows original C code from limit_syscalls
      
      const char* syscall_name = strtok(buf, ",");

      int syscall = seccomp_syscall_resolve_name(buf);
      
      if (syscall == __NR_SCMP_ERROR) {
          ERR_CONCAT("Unknown syscall: ", syscall_name);
      }
      
      int nargs = 0;
      struct scmp_arg_cmp args[6];
      
      uint32_t action = SCMP_ACT_ALLOW;
      
      const char* aa = strtok(NULL, ",");
      for (;aa; aa=strtok(NULL, ",")) {
          if (aa[0]=='A') {
              if(nargs==6) {
                  ERR_STR("Maximum comparator count (6) exceed in ", arg);
              }
              if( !(aa[1]>='0' && aa[1]<='5') ) {
                  ERR_STR("A[0-5] expected; in ", arg);
              }
              int cmp = 0; /* invalid value */
              
              if(!strncmp(aa+2, "!=", 2)) cmp=SCMP_CMP_NE;
              if(!strncmp(aa+2, "<<", 2)) cmp=SCMP_CMP_LT;
              if(!strncmp(aa+2, "<=", 2)) cmp=SCMP_CMP_LE;
              if(!strncmp(aa+2, "==", 2)) cmp=SCMP_CMP_EQ;
              if(!strncmp(aa+2, ">=", 2)) cmp=SCMP_CMP_GE;
              if(!strncmp(aa+2, ">>", 2)) cmp=SCMP_CMP_GT;
              if(!strncmp(aa+2, "&&", 2)) cmp=SCMP_CMP_MASKED_EQ;
                  
              if (!cmp) {
                  ERR_STR("After An there should be comparison operator like"
                          " != << <= == => >> ot &&; in ", arg);
              }
              
              if (cmp != SCMP_CMP_MASKED_EQ) {
                  scmp_datum_t datum;
                  if(sscanf(aa+4, "%lli", &datum)!=1) {
                      ERR_STR("After AxOP there should be some sort of number; in ", arg);
                  }
                  
                  args[nargs++] = SCMP_CMP(aa[1]-'0', cmp, datum);
              } else {
                  scmp_datum_t mask;
                  scmp_datum_t datum;
                  if(sscanf(aa+4, "%lli==%lli", &mask, &datum)!=2) {
                      ERR_STR("After Ax&& there should be number==number; in ", arg);
                  }
                  
                  args[nargs++] = SCMP_CMP(aa[1]-'0', SCMP_CMP_MASKED_EQ, mask, datum);
              }
          } else
          if (aa[0]=='e') {
              int errno_;
              if (sscanf(aa+1,"%i", &errno_)!=1) {
                  ERR_STR("After e should be number in ", arg);
              }
              
              action = SCMP_ACT_ERRNO(errno_);
          } else
          if (aa[0]=='k') {
              action = SCMP_ACT_KILL;
          } else
          if (aa[0]=='a') {
              action = SCMP_ACT_ALLOW;
          } else {
              ERR_STR("Unknown action in ", arg);
          }
      }
      
      ret = seccomp_rule_add_hack(ctx, action, syscall, nargs, args);
      // seccomp_export_pfc(ctx, 1);
      if (ret!=0) {
          ERR_CUSTOM(
              String::Concat(
                String::Concat(
                  String::Concat(
                    String::New("seccomp_rule_add returned "),
                    Integer::New(ret)->ToString()),
                  String::New(" for rule: ")),
                arg));
      }
  }
  free(buf);
  ret = seccomp_load(ctx);
  if (ret != 0) {
    ERR_INT("seccomp_load returned ", ret);
  }
  seccomp_release(ctx);
  
  return scope.Close(Undefined());
}

void Init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("enter"),
      FunctionTemplate::New(Seccomp)->GetFunction());
}

NODE_MODULE(seccomp_filter, Init)
