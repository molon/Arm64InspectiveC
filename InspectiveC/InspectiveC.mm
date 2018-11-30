#include "InspectiveC.h"
#include <Foundation/Foundation.h>

#include <cstdarg>
#include <cstdio>

#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>

#import <fishhook/fishhook.h>
#import <objc/runtime.h>

#include "hashmap.h"
#include "logging.h"

// Optional - comment this out if you want to log on ALL threads (laggy due to rw-locks).
#define MAIN_THREAD_ONLY

#define MAX_PATH_LENGTH 1024

#define DEFAULT_CALLSTACK_DEPTH 128
#define CALLSTACK_DEPTH_INCREMENT 64

#define DEFAULT_MAX_RELATIVE_RECURSIVE_DESCENT_DEPTH 64

//#ifdef MAIN_THREAD_ONLY

#define RLOCK
#define WLOCK
#define UNLOCK

//#else
//
//static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
//
//#define RLOCK pthread_rwlock_rdlock(&lock)
//#define WLOCK pthread_rwlock_wrlock(&lock)
//#define UNLOCK pthread_rwlock_unlock(&lock)
//
//#endif

#define WATCH_ALL_SELECTORS_SELECTOR NULL

#if __arm64__
#define arg_list pa_list
#else
#define arg_list va_list
#endif

#ifdef MAIN_THREAD_ONLY
static void performBlockOnProperThread(void (^block)(void)) {
  if (pthread_main_np()) {
    block();
  } else {
    dispatch_async(dispatch_get_main_queue(), block);
  }
}
#else
static void performBlockOnProperThread(void (^block)(void)) {
  WLOCK;
  block();
  UNLOCK;
}
#endif

// The original objc_msgSend.
static id (*orig_objc_msgSend)(id, SEL, ...) = NULL;

// These classes support handling of void *s using callback functions, yet their methods
// accept (fake) ids. =/ i.e. objectForKey: and setObject:forKey: are dangerous for us because what
// looks like an id can be a regular old int and crash our program...
static Class NSMapTable_Class;
static Class NSHashTable_Class;

// We have to call [<self> class] when logging to make sure that the class is initialized.
static SEL class_SEL = @selector(class);

static HashMapRef objectsMap;
static HashMapRef classMap;
static HashMapRef selsSet;
static pthread_key_t threadKey;
static const char *directory;

// Max callstack depth to log after the last hit.
static int maxRelativeRecursiveDepth = DEFAULT_MAX_RELATIVE_RECURSIVE_DESCENT_DEPTH;

// HashMap functions.
static int pointerEquality(void *a, void *b) {
  uintptr_t ia = reinterpret_cast<uintptr_t>(a);
  uintptr_t ib = reinterpret_cast<uintptr_t>(b);
  return ia == ib;
}

#ifdef __arm64__
// 64 bit hash from https://gist.github.com/badboy/6267743.
static inline NSUInteger pointerHash(void *v) {
  uintptr_t key = reinterpret_cast<uintptr_t>(v);
  key = (~key) + (key << 21); // key = (key << 21) - key - 1;
  key = key ^ (key >> 24);
  key = (key + (key << 3)) + (key << 8); // key * 265
  key = key ^ (key >> 14);
  key = (key + (key << 2)) + (key << 4); // key * 21
  key = key ^ (key >> 28);
  key = key + (key << 31);
  return key;
}
#else
// Robert Jenkin's 32 bit int hash.
static inline NSUInteger pointerHash(void *v) {
  uintptr_t a = reinterpret_cast<uintptr_t>(v);
  a = (a + 0x7ed55d16) + (a << 12);
  a = (a ^ 0xc761c23c) ^ (a >> 19);
  a = (a + 0x165667b1) + (a << 5);
  a = (a + 0xd3a2646c) ^ (a << 9);
  a = (a + 0xfd7046c5) + (a << 3);
  a = (a ^ 0xb55a4f09) ^ (a >> 16);
  return (NSUInteger)a;
}
#endif

// Shared structures.
typedef struct CallRecord_ {
  id obj;
  SEL _cmd;
  uintptr_t lr;
  int prevHitIndex; // Only used if isWatchHit is set.
  char isWatchHit;
} CallRecord;

typedef struct ThreadCallStack_ {
  FILE *file;
  char *spacesStr;
  CallRecord *stack;
  int allocatedLength;
  int index;
  int numWatchHits;
  int lastPrintedIndex;
  int lastHitIndex;
  char isLoggingEnabled;
  char isCompleteLoggingEnabled;
} ThreadCallStack;

static inline void mapAddSelector(HashMapRef map, id obj_or_class, SEL _cmd) {
  HashMapRef selectorSet = (HashMapRef)HMGet(map, (void *)obj_or_class);
  if (selectorSet == NULL) {
    selectorSet = HMCreate(&pointerEquality, &pointerHash);
    HMPut(map, (void *)obj_or_class, selectorSet);
  }

  HMPut(selectorSet, _cmd, (void *)YES);
}

static inline void mapDestroySelectorSet(HashMapRef map, id obj_or_class) {
  HashMapRef selectorSet = (HashMapRef)HMRemove(map, (void *)obj_or_class);
  if (selectorSet != NULL) {
    HMFree(selectorSet);
  }
}

static inline void selectorSetRemoveSelector(HashMapRef selectorSet, SEL _cmd) {
  if (selectorSet != NULL) {
    HMRemove(selectorSet, _cmd);
  }
}

// Inspective C Public API.

extern "C" void InspectiveC_setMaximumRelativeLoggingDepth(int depth) {
  if (depth >= 0) {
    maxRelativeRecursiveDepth = depth;
  }
}

extern "C" void InspectiveC_watchObject(id obj) {
  if (obj == nil) {
    return;
  }
  performBlockOnProperThread(^(){
      mapAddSelector(objectsMap, obj, WATCH_ALL_SELECTORS_SELECTOR);
  });
}
extern "C" void InspectiveC_unwatchObject(id obj) {
  if (obj == nil) {
    return;
  }
  performBlockOnProperThread(^(){
      mapDestroySelectorSet(objectsMap, obj);
  });
}

extern "C" void InspectiveC_watchSelectorOnObject(id obj, SEL _cmd) {
  if (obj == nil || _cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      mapAddSelector(objectsMap, obj, _cmd);
  });
}
extern "C" void InspectiveC_unwatchSelectorOnObject(id obj, SEL _cmd) {
  if (obj == nil || _cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      selectorSetRemoveSelector((HashMapRef)HMGet(objectsMap, obj), _cmd);
  });
}

extern "C" void InspectiveC_watchInstancesOfClass(Class clazz) {
  if (clazz == nil) {
    return;
  }
  performBlockOnProperThread(^(){
      mapAddSelector(classMap, clazz, WATCH_ALL_SELECTORS_SELECTOR);
  });
}
extern "C" void InspectiveC_unwatchInstancesOfClass(Class clazz) {
  if (clazz == nil) {
    return;
  }
  performBlockOnProperThread(^(){
      mapDestroySelectorSet(classMap, clazz);
  });
}

extern "C" void InspectiveC_watchSelectorOnInstancesOfClass(Class clazz, SEL _cmd) {
  if (clazz == nil || _cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      mapAddSelector(classMap, clazz, _cmd);
  });
}
extern "C" void InspectiveC_unwatchSelectorOnInstancesOfClass(Class clazz, SEL _cmd) {
  if (clazz == nil || _cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      selectorSetRemoveSelector((HashMapRef)HMGet(classMap, clazz), _cmd);
  });
}

extern "C" void InspectiveC_watchSelector(SEL _cmd) {
  if (_cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      HMPut(selsSet, (void *)_cmd, (void *)_cmd);
  });
}
extern "C" void InspectiveC_unwatchSelector(SEL _cmd) {
  if (_cmd == NULL) {
    return;
  }
  performBlockOnProperThread(^(){
      HMRemove(selsSet, (void *)_cmd);
  });
}

static inline ThreadCallStack * getThreadCallStack();

// Enables/disables logging every message.
extern "C" void InspectiveC_enableCompleteLogging() {
  ThreadCallStack *cs = getThreadCallStack();
  cs->isCompleteLoggingEnabled = 1;
}

extern "C" void InspectiveC_disableCompleteLogging() {
  ThreadCallStack *cs = getThreadCallStack();
  cs->isCompleteLoggingEnabled = 0;
}

// Semi Public API - used to temporarily disable logging.

extern "C" void InspectiveC_enableLogging() {
  ThreadCallStack *cs = getThreadCallStack();
  cs->isLoggingEnabled = 1;
}

extern "C" void InspectiveC_disableLogging() {
  ThreadCallStack *cs = getThreadCallStack();
  cs->isLoggingEnabled = 0;
}

extern "C" int InspectiveC_isLoggingEnabled() {
  ThreadCallStack *cs = getThreadCallStack();
  return (int)cs->isLoggingEnabled;
}


extern "C" void InspectiveC_flushLogFile() {
  ThreadCallStack *cs = getThreadCallStack();
  FILE *logFile = cs->file;
  if (logFile) {
    fflush(logFile);
  }
}

// Shared functions.
extern "C" char ***_NSGetArgv(void);

static FILE * newFileForThread() {
  const char *exeName = **_NSGetArgv();
  if (exeName == NULL) {
    exeName = "(NULL)";
  } else if (const char *slash = strrchr(exeName, '/')) {
    exeName = slash + 1;
  }

  pid_t pid = getpid();
  char path[MAX_PATH_LENGTH];

  sprintf(path, "%s/InspectiveC", directory);
  mkdir(path, 0755);
  sprintf(path, "%s/InspectiveC/%s", directory, exeName);
  mkdir(path, 0755);

  if (pthread_main_np()) {
    sprintf(path, "%s/InspectiveC/%s/%d_main.log", directory, exeName, pid);
  } else {
    mach_port_t tid = pthread_mach_thread_np(pthread_self());
    sprintf(path, "%s/InspectiveC/%s/%d_t%u.log", directory, exeName, pid, tid);
  }
  return fopen(path, "a");
}

static inline ThreadCallStack * getThreadCallStack() {
  ThreadCallStack *cs = (ThreadCallStack *)pthread_getspecific(threadKey);
  if (cs == NULL) {
    cs = (ThreadCallStack *)malloc(sizeof(ThreadCallStack));
#ifdef MAIN_THREAD_ONLY
    cs->file = (pthread_main_np()) ? newFileForThread() : NULL;
#else
    cs->file = newFileForThread();
#endif
    cs->isLoggingEnabled = (cs->file != NULL);
    cs->isCompleteLoggingEnabled = 0;
    cs->spacesStr = (char *)malloc(DEFAULT_CALLSTACK_DEPTH + 1);
    memset(cs->spacesStr, ' ', DEFAULT_CALLSTACK_DEPTH);
    cs->spacesStr[DEFAULT_CALLSTACK_DEPTH] = '\0';
    cs->stack = (CallRecord *)calloc(DEFAULT_CALLSTACK_DEPTH, sizeof(CallRecord));
    cs->allocatedLength = DEFAULT_CALLSTACK_DEPTH;
    cs->index = cs->lastPrintedIndex = cs->lastHitIndex = -1;
    cs->numWatchHits = 0;
    pthread_setspecific(threadKey, cs);
  }
  return cs;
}

static void destroyThreadCallStack(void *ptr) {
  ThreadCallStack *cs = (ThreadCallStack *)ptr;
  if (cs->file) {
    fclose(cs->file);
  }
  free(cs->spacesStr);
  free(cs->stack);
  free(cs);
}

static inline void pushCallRecord(id obj, uintptr_t lr, SEL _cmd, ThreadCallStack *cs) {
  int nextIndex = (++cs->index);
  if (nextIndex >= cs->allocatedLength) {
    cs->allocatedLength += CALLSTACK_DEPTH_INCREMENT;
    cs->stack = (CallRecord *)realloc(cs->stack, cs->allocatedLength * sizeof(CallRecord));
    cs->spacesStr = (char *)realloc(cs->spacesStr, cs->allocatedLength + 1);
    memset(cs->spacesStr, ' ', cs->allocatedLength);
    cs->spacesStr[cs->allocatedLength] = '\0';
  }
  CallRecord *newRecord = &cs->stack[nextIndex];
  newRecord->obj = obj;
  newRecord->_cmd = _cmd;
  newRecord->lr = lr;
  newRecord->isWatchHit = 0;
}

static inline CallRecord * popCallRecord(ThreadCallStack *cs) {
  return &cs->stack[cs->index--];
}

static inline BOOL isKindOfClass(Class selfClass, Class clazz) {
  for (Class candidate = selfClass; candidate; candidate = class_getSuperclass(candidate)) {
    if (candidate == clazz) {
      return YES;
    }
  }
  return NO;
}

static inline BOOL classSupportsArbitraryPointerTypes(Class clazz) {
  return isKindOfClass(clazz, NSMapTable_Class) || isKindOfClass(clazz, NSHashTable_Class);
}

static inline void log(FILE *file, id obj, SEL _cmd, char *spaces) {
  Class kind = object_getClass(obj);
  bool isMetaClass = class_isMetaClass(kind);
  if (isMetaClass) {
    printf("%s%s+|%s %s|\n", spaces, spaces, class_getName(kind), sel_getName(_cmd));
  } else {
    printf("%s%s-|%s %s| @<%p>\n", spaces, spaces, class_getName(kind), sel_getName(_cmd), (void *)obj);
  }
}

static inline void logWithArgs(ThreadCallStack *cs, FILE *file, id obj, SEL _cmd, char *spaces,
    arg_list &args, Class kind, BOOL isMetaClass, BOOL isWatchHit) {
  Method method = (isMetaClass) ? class_getClassMethod(kind, _cmd) : class_getInstanceMethod(kind, _cmd);
  if (method) {
    const char *normalFormatStr;
    const char *metaClassFormatStr;

    if (isWatchHit) {
      normalFormatStr = "%s%s***-|%s@<%p> %s|";
      metaClassFormatStr = "%s%s***+|%s %s|";
    } else {
      normalFormatStr = "%s%s-|%s@<%p> %s|";
      metaClassFormatStr = "%s%s+|%s %s|";
    }

    if (isMetaClass) {
      printf(metaClassFormatStr, spaces, spaces, class_getName(kind), sel_getName(_cmd));
    } else {
      printf(normalFormatStr, spaces, spaces, class_getName(kind), (void *)obj, sel_getName(_cmd));
    }
    const char *typeEncoding = method_getTypeEncoding(method);
    if (!typeEncoding || classSupportsArbitraryPointerTypes(kind)) {
      printf((isWatchHit) ? " ~NO ENCODING~***\n" : " ~NO ENCODING~\n");
      return;
    }

    cs->isLoggingEnabled = 0;
    @try {
      NSMethodSignature *signature = [NSMethodSignature signatureWithObjCTypes:typeEncoding];
      const NSUInteger numberOfArguments = [signature numberOfArguments];
      for (NSUInteger index = 2; index < numberOfArguments; ++index) {
        const char *type = [signature getArgumentTypeAtIndex:index];
        printf(" ");
        if (!logArgument(file, type, args)) { // Can't understand arg - probably a struct.
          printf("~BAIL on \"%s\"~", type);
          break;
        }
      }
    } @catch(NSException *e) {
      printf("~BAD ENCODING~");
    }
    printf((isWatchHit) ? "***\n" : "\n");
    cs->isLoggingEnabled = 1;
  }
}

static inline void logWatchedHit(ThreadCallStack *cs, FILE *file, id obj, SEL _cmd, char *spaces, arg_list &args) {
  Class kind = object_getClass(obj);
  BOOL isMetaClass = class_isMetaClass(kind);

  logWithArgs(cs, file, obj, _cmd, spaces, args, kind, isMetaClass, YES);
}

static inline void logObjectAndArgs(ThreadCallStack *cs, FILE *file, id obj, SEL _cmd, char *spaces, arg_list &args) {

  // Call [<obj> class] to make sure the class is initialized.
  Class kind = ((Class (*)(id, SEL))orig_objc_msgSend)(obj, class_SEL);
  BOOL isMetaClass = (kind == obj);

  logWithArgs(cs, file, obj, _cmd, spaces, args, kind, isMetaClass, NO);
}

static inline void onWatchHit(ThreadCallStack *cs, arg_list &args) {
  const int hitIndex = cs->index;
  CallRecord *hitRecord = &cs->stack[hitIndex];
  hitRecord->isWatchHit = 1;
  hitRecord->prevHitIndex = cs->lastHitIndex;
  cs->lastHitIndex = hitIndex;
  ++cs->numWatchHits;

  FILE *logFile = cs->file;
  if (logFile) {

    // Log previous calls if necessary.
    for (int i = cs->lastPrintedIndex + 1; i < hitIndex; ++i) {
      CallRecord record = cs->stack[i];

      // Modify spacesStr.
      char *spaces = cs->spacesStr;
      spaces[i] = '\0';
      log(logFile, record.obj, record._cmd, spaces);

      // Clean up spacesStr.
      spaces[i] = ' ';
    }

    // Log the hit call.
    char *spaces = cs->spacesStr;
    spaces[hitIndex] = '\0';
    logWatchedHit(cs, logFile, hitRecord->obj, hitRecord->_cmd, spaces, args);

    // Clean up spacesStr.
    spaces[hitIndex] = ' ';

    // Lastly, set the lastPrintedIndex.
    cs->lastPrintedIndex = hitIndex;
  }
}

static inline void onNestedCall(ThreadCallStack *cs, arg_list &args) {
  const int curIndex = cs->index;
  FILE *logFile = cs->file;
  if (logFile &&
     (cs->isCompleteLoggingEnabled || (curIndex - cs->lastHitIndex) <= maxRelativeRecursiveDepth)) {

    // Log the current call.
    char *spaces = cs->spacesStr;
    spaces[curIndex] = '\0';
    CallRecord curRecord = cs->stack[curIndex];
    logObjectAndArgs(cs, logFile, curRecord.obj, curRecord._cmd, spaces, args);
    spaces[curIndex] = ' ';

    // Lastly, set the lastPrintedIndex.
    cs->lastPrintedIndex = curIndex;
  }
}

static inline BOOL selectorSetContainsSelector(HashMapRef selectorSet, SEL _cmd) {
  if (selectorSet == NULL) {
    return NO;
  }
  return HMGet(selectorSet, WATCH_ALL_SELECTORS_SELECTOR) != NULL ||
      HMGet(selectorSet, _cmd) != NULL;
}

static inline void preObjc_msgSend_common(id self, uintptr_t lr, SEL _cmd, ThreadCallStack *cs, arg_list &args) {
#ifdef MAIN_THREAD_ONLY
  if (self && pthread_main_np() && cs->isLoggingEnabled) {
#else
  if (self && cs->isLoggingEnabled) {
#endif
    Class clazz = object_getClass(self);
    RLOCK;
    // Critical section - check for hits.
    BOOL isWatchedObject = selectorSetContainsSelector((HashMapRef)HMGet(objectsMap, (void *)self), _cmd);
    BOOL isWatchedClass = selectorSetContainsSelector((HashMapRef)HMGet(classMap, (void *)clazz), _cmd);
    BOOL isWatchedSel = (HMGet(selsSet, (void *)_cmd) != NULL);
    UNLOCK;
    if (isWatchedObject && _cmd == @selector(dealloc)) {
      WLOCK;
      mapDestroySelectorSet(objectsMap, self);
      UNLOCK;
    }
    if (isWatchedObject || isWatchedClass || isWatchedSel) {
      onWatchHit(cs, args);
    } else if (cs->numWatchHits > 0 || cs->isCompleteLoggingEnabled) {
      onNestedCall(cs, args);
    }
  }
}

// Called in our replacementObjc_msgSend after calling the original objc_msgSend.
// This returns the lr in r0/x0.
uintptr_t postObjc_msgSend();
uintptr_t postObjc_msgSend() {
  ThreadCallStack *cs = (ThreadCallStack *)pthread_getspecific(threadKey);
  CallRecord *record = popCallRecord(cs);
  if (record->isWatchHit) {
    --cs->numWatchHits;
    cs->lastHitIndex = record->prevHitIndex;
  }
  if (cs->lastPrintedIndex > cs->index) {
    cs->lastPrintedIndex = cs->index;
  }
  return record->lr;
}

// 32-bit vs 64-bit stuff.
#ifdef __arm64__
    // 64-bit stuff.
    struct PointerAndInt_ {
        uintptr_t ptr;
        int i;
    };
    
    // arm64 hooking magic.
    
    // Called in our replacementObjc_msgSend before calling the original objc_msgSend.
    // This pushes a CallRecord to our stack, most importantly saving the lr.
    // Returns orig_objc_msgSend in x0 and isLoggingEnabled in x1.
    struct PointerAndInt_ preObjc_msgSend(id self, uintptr_t lr, SEL _cmd, struct RegState_ *rs);
    struct PointerAndInt_ preObjc_msgSend(id self, uintptr_t lr, SEL _cmd, struct RegState_ *rs) {
        ThreadCallStack *cs = getThreadCallStack();
        pushCallRecord(self, lr, _cmd, cs);
        
        pa_list args = (pa_list){ rs, ((unsigned char *)rs) + 208, 2, 0 }; // 208 is the offset of rs from the top of the stack.
        preObjc_msgSend_common(self, lr, _cmd, cs, args);
        
        return (struct PointerAndInt_) {reinterpret_cast<uintptr_t>(orig_objc_msgSend), 1};
    }
    
    // Our replacement objc_msgSend (arm64).
    //
    // See:
    // https://blog.nelhage.com/2010/10/amd64-and-va_arg/
    // http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf
    // https://developer.apple.com/library/ios/documentation/Xcode/Conceptual/iPhoneOSABIReference/Articles/ARM64FunctionCallingConventions.html
    __attribute__((__naked__))
    static void replacementObjc_msgSend() {
        __asm__ volatile (
                          // push {q0-q7}
                          "stp q6, q7, [sp, #-32]!\n"
                          "stp q4, q5, [sp, #-32]!\n"
                          "stp q2, q3, [sp, #-32]!\n"
                          "stp q0, q1, [sp, #-32]!\n"
                          // push {x0-x8, lr}
                          "stp x8, lr, [sp, #-16]!\n"
                          "stp x6, x7, [sp, #-16]!\n"
                          "stp x4, x5, [sp, #-16]!\n"
                          "stp x2, x3, [sp, #-16]!\n"
                          "stp x0, x1, [sp, #-16]!\n"
                          // Swap args around for call.
                          "mov x2, x1\n"
                          "mov x1, lr\n"
                          "mov x3, sp\n"
                          // Call preObjc_msgSend which puts orig_objc_msgSend into x0 and isLoggingEnabled into x1.
                          "bl __Z15preObjc_msgSendP11objc_objectmP13objc_selectorP9RegState_\n"
                          "mov x9, x0\n"
                          "mov x10, x1\n"
                          "tst x10, x10\n" // Set condition code for later branch.
                          // pop {x0-x8, lr}
                          "ldp x0, x1, [sp], #16\n"
                          "ldp x2, x3, [sp], #16\n"
                          "ldp x4, x5, [sp], #16\n"
                          "ldp x6, x7, [sp], #16\n"
                          "ldp x8, lr, [sp], #16\n"
                          // pop {q0-q7}
                          "ldp q0, q1, [sp], #32\n"
                          "ldp q2, q3, [sp], #32\n"
                          "ldp q4, q5, [sp], #32\n"
                          "ldp q6, q7, [sp], #32\n"
                          // Make sure it's enabled.
                          "b.eq Lpassthrough\n"
                          // Call through to the original objc_msgSend.
                          "blr x9\n"
                          // push {x0-x9}
                          "stp x0, x1, [sp, #-16]!\n"
                          "stp x2, x3, [sp, #-16]!\n"
                          "stp x4, x5, [sp, #-16]!\n"
                          "stp x6, x7, [sp, #-16]!\n"
                          "stp x8, x9, [sp, #-16]!\n" // Not sure if needed - push for alignment.
                          // push {q0-q7}
                          "stp q0, q1, [sp, #-32]!\n"
                          "stp q2, q3, [sp, #-32]!\n"
                          "stp q4, q5, [sp, #-32]!\n"
                          "stp q6, q7, [sp, #-32]!\n"
                          // Call our postObjc_msgSend hook.
                          "bl __Z16postObjc_msgSendv\n"
                          "mov lr, x0\n"
                          // pop {q0-q7}
                          "ldp q6, q7, [sp], #32\n"
                          "ldp q4, q5, [sp], #32\n"
                          "ldp q2, q3, [sp], #32\n"
                          "ldp q0, q1, [sp], #32\n"
                          // pop {x0-x9}
                          "ldp x8, x9, [sp], #16\n"
                          "ldp x6, x7, [sp], #16\n"
                          "ldp x4, x5, [sp], #16\n"
                          "ldp x2, x3, [sp], #16\n"
                          "ldp x0, x1, [sp], #16\n"
                          "ret\n"
                          
                          // Pass through to original objc_msgSend.
                          "Lpassthrough:\n"
                          "br x9"
                          );
    }
#else

    // arm32 hooking magic.
    
    // Called in our replacementObjc_msgSend before calling the original objc_msgSend.
    // This pushes a CallRecord to our stack, most importantly saving the lr.
    // Returns orig_objc_msgSend.
    uintptr_t preObjc_msgSend(id self, uintptr_t lr, SEL _cmd, va_list args);
    uintptr_t preObjc_msgSend(id self, uintptr_t lr, SEL _cmd, va_list args) {
        ThreadCallStack *cs = getThreadCallStack();
        pushCallRecord(self, lr, _cmd, cs);
        
        preObjc_msgSend_common(self, lr, _cmd, cs, args);
        
        return reinterpret_cast<uintptr_t>(orig_objc_msgSend);
    }
    
    // Our replacement objc_msgSend for arm32.
    __attribute__((__naked__))
    static void replacementObjc_msgSend() {
        __asm__ volatile (
                          // Make sure it's enabled.
                          "push {r0-r3, lr}\n"
                          "blx _InspectiveC_isLoggingEnabled\n"
                          "mov r12, r0\n"
                          "pop {r0-r3, lr}\n"
                          "ands r12, r12\n"
                          "beq Lpassthrough\n"
                          // Call our preObjc_msgSend hook - returns orig_objc_msgSend.
                          // Swap the args around for our call to preObjc_msgSend.
                          "push {r0, r1, r2, r3}\n"
                          "mov r2, r1\n"
                          "mov r1, lr\n"
                          "add r3, sp, #8\n"
                          "blx __Z15preObjc_msgSendP11objc_objectmP13objc_selectorPv\n"
                          "mov r12, r0\n"
                          "pop {r0, r1, r2, r3}\n"
                          // Call through to the original objc_msgSend.
                          "blx r12\n"
                          // Call our postObjc_msgSend hook.
                          "push {r0-r3}\n"
                          "blx __Z16postObjc_msgSendv\n"
                          "mov lr, r0\n"
                          "pop {r0-r3}\n"
                          "bx lr\n"
                          // Pass through to original objc_msgSend.
                          "Lpassthrough:\n"
                          "movw  r12, :lower16:(__ZL17orig_objc_msgSend-(Loffset+4))\n"
                          "movt  r12, :upper16:(__ZL17orig_objc_msgSend-(Loffset+4))\n"
                          "Loffset:\n"
                          "add r12, pc\n"
                          "ldr r12, [r12]\n"
                          "bx r12\n"
                          );
    }
#endif

static void hook() {
  rebind_symbols((struct rebinding[1]){{"objc_msgSend", (void *)replacementObjc_msgSend, (void **)&orig_objc_msgSend}}, 1);
}

// Edited by github.com/molon
static bool isInitialized;
    
bool InspectiveC_IsInitialize() {
    return isInitialized;
}
    
#ifdef __arm64__
void InspectiveC_Initialize() {
    if (isInitialized) {
        return;
    }
    
  isInitialized = true;
    
  pthread_key_create(&threadKey, &destroyThreadCallStack);

  NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
  NSString *path = [paths firstObject];
  directory = [path UTF8String];

#ifdef MAIN_THREAD_ONLY
  NSLog(@"[InspectiveC] Loading - Directory is \"%s\"", directory);
#else
  NSLog(@"[InspectiveC] Multithreaded; Loading - Directory is \"%s\"", directory);
#endif

  NSMapTable_Class = [objc_getClass("NSMapTable") class];
  NSHashTable_Class = [objc_getClass("NSHashTable") class];

  objectsMap = HMCreate(&pointerEquality, &pointerHash);
  classMap = HMCreate(&pointerEquality, &pointerHash);
  selsSet = HMCreate(&pointerEquality, &pointerHash);

  hook();
}

@implementation NSObject(____InspectiveC)
+ (void)load{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
//        InspectiveC_Initialize();
    });
}
@end
#endif
