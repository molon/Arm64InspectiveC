#include "blocks.h"

#include <objc/runtime.h>

// Thanks to CTObjectiveCRuntimeAdditions (https://github.com/ebf/CTObjectiveCRuntimeAdditions).
// See http://clang.llvm.org/docs/Block-ABI-Apple.html.
void logBlock(FILE *file, id block) {
  struct BlockLiteral_ *blockRef = (__bridge struct BlockLiteral_ *)block;
  int flags = blockRef->flags;

  const char *signature = NULL;

  if (flags & BLOCK_HAS_SIGNATURE) {
    unsigned char *signatureLocation = (unsigned char *)blockRef->descriptor;
    signatureLocation += sizeof(unsigned long int);
    signatureLocation += sizeof(unsigned long int);

    if (flags & BLOCK_HAS_COPY_DISPOSE) {
      signatureLocation += sizeof(void (*)(void *, void *));
      signatureLocation += sizeof(void (*)(void *));
    }

    signature = (*(const char **)signatureLocation);
  }

  if (signature) {
    NSMethodSignature *methodSignature = [NSMethodSignature signatureWithObjCTypes:signature];
    Class kind = object_getClass(block);
    printf("<%s@%p signature=\"%s ; retType=%s", class_getName(kind), (void *)block, signature, methodSignature.methodReturnType);

    // Skip the first argument (self).
    NSUInteger numOfArgs = methodSignature.numberOfArguments;
    for (NSUInteger i = 1; i < numOfArgs; ++i) {
      printf(" %u=%s", (unsigned)i, [methodSignature getArgumentTypeAtIndex:i]);
    }
    printf("\">");
  } else {
    Class kind = object_getClass(block);
    printf("<%s@%p>", class_getName(kind), (void *)block);
  }
}
