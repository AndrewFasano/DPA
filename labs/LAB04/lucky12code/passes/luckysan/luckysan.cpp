
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "helloputs"

STATISTIC(PutsCounter, "Counts number of puts functions we analyzed");

// anonymous namespace -> avoid exporting unneeded symbols
namespace {
  struct LuckySan : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    llvm::FunctionCallee StrcmpFunc;
    llvm::FunctionCallee ExitFunc;
    llvm::FunctionCallee PutsFunc;
    llvm::FunctionCallee StrstrFunc;
    LuckySan() : FunctionPass(ID) {}

    // Responsible for ensuring the symbol `exit` is available in every module.
    // This function is allowed to modify the global state of the program
    bool doInitialization(Module &M);


	  // This function examines each function individually, it is not
    // allowed to share any state between functions
    bool runOnFunction(Function &F);
  };
}

bool LuckySan::doInitialization(Module &M) {
    // https://llvm.org/docs/WritingAnLLVMPass.html#the-doinitialization-module-method
    errs() << "Initialize our pass for the current module\n";
    // These messages printed to errs() are printed when our pass runs, *not* when the
    // resulting binary is run

    LLVMContext &context = M.getContext();
    ExitFunc = M.getOrInsertFunction(
                                      "exit",                         // name of function
                                      Type::getVoidTy(context),       // return type
                                      Type::getInt32Ty(context)       // first arg: int32
                                    );
    StrcmpFunc = M.getOrInsertFunction(
                                        "strcmp",                         // name of function
                                        Type::getInt1Ty(context),         // returns a 1-bit int, aka a bool
                                         PointerType::getUnqual(IntegerType::getInt8Ty(context)),         // arg1: char* (int8t)
                                         PointerType::getUnqual(IntegerType::getInt8Ty(context))         // arg2: char* (int8t)
                                      );

    StrstrFunc = M.getOrInsertFunction(
                                        "strstr",                         // name of function
                                         //PointerType::getUnqual(IntegerType::getInt8Ty(context)),         // return value, char*
                                    	 Type::getInt32Ty(context),        // returns an integer (lie)
                                         PointerType::getUnqual(IntegerType::getInt8Ty(context)),         // arg1: char* (int8t)
                                         PointerType::getUnqual(IntegerType::getInt8Ty(context))         // arg2: char* (int8t)
		                   );

    PutsFunc = M.getOrInsertFunction(
                                      "puts",                           // name of function
                                      Type::getInt32Ty(context),        // returns an integer
                                       PointerType::getUnqual(IntegerType::getInt8Ty(context))         // arg: char* (int8t)
                                    );

    return true;
}

bool LuckySan::runOnFunction(Function &F) {
  errs() << "Visiting function " << F.getName() << "\n";

  // Loop over each block in the function
  for (BasicBlock &BB : F) {
      // Loop over each instruction in the block
      for (Instruction &II : BB) {
        // For each instruction, let's examine it
        Instruction *I = &II;

        // Check if it's a call isntruction
        if (CallInst *CI = dyn_cast<CallInst>(I)) {

          // If we have debug information, record the source location of each call.
          if (DILocation *Loc = I->getDebugLoc()) {
            unsigned Line = Loc->getLine();
            StringRef File = Loc->getFilename();
            StringRef Dir = Loc->getDirectory();
            errs() << "Call instruction at " << Dir << "/" << File << ":" << Line << "\n";
          }

          // If we can get the name of the function being called, examine and possibly modify it
          if (Function *calledFunction = CI->getCalledFunction()) {
            errs() << "Function: " << calledFunction->getName() << "\n";
            if (calledFunction->getName() == "puts") {
              ++PutsCounter;

              // To get a Value* for the x in puts(x) , we need to examine the operands to the instruction
              // instead of iterating through the Function arguments directly, otherwise LLVM gets mad
              Value* argVal = I->getOperand(0);

              // Create an IR Builder object and use it to insert some function calls just before
              // the current instruction
              IRBuilder<> builder(I);
              Value *strPtr = builder.CreateGlobalStringPtr(StringRef("[LuckySan] detected that there's about to be a puts of the following string:"));
              Value *strPtr2 = builder.CreateGlobalStringPtr(StringRef("[LuckySan] now let's keep going"));

              Value *thirteen = builder.CreateGlobalStringPtr(StringRef("13"));

              builder.CreateCall(PutsFunc, strPtr);   // Our message
              builder.CreateCall(PutsFunc, argVal);   // original message
              builder.CreateCall(PutsFunc, strPtr2);  // second message

	      std::vector<Value*> args = {thirteen, strPtr};
              Value *result = builder.CreateCall(StrstrFunc, args);   // do compare
	      Value *zero = builder.getInt32(0);
	      Value *cmp = builder.CreateICmpEQ(result, zero);
            }
          }
        }
      }
    }

  return false;
}



char LuckySan::ID = 0;
static RegisterPass<LuckySan>
Y("luckysan", "Lucky 12 Sanitizer Pass");
