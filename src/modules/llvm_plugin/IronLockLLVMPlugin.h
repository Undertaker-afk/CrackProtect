#pragma once
/**
 * IronLock LLVM Plugin - Direct Compilation Pipeline Integration
 * 
 * This plugin integrates IronLock protection directly into the LLVM/Clang
 * compilation pipeline, allowing for smarter obfuscation at the IR level.
 * 
 * Features:
 * - Function-level protection markers via attributes
 * - Control Flow Flattening at IR level
 * - Virtualization candidates identification
 * - String encryption at compile time
 * - Opaque predicate insertion
 * 
 * Usage:
 *   clang -Xclang -load -Xclang IronLockLLVMPlugin.so source.cpp
 */

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

namespace ironlock {

// Command line options for the plugin
extern llvm::cl::opt<bool> EnableCFF;
extern llvm::cl::opt<bool> EnableVirtualization;
extern llvm::cl::opt<bool> EnableStringEncryption;
extern llvm::cl::opt<bool> EnableOpaquePredicates;
extern llvm::cl::opt<std::string> ProtectionProfile;

/**
 * IronLockProtectionMarker - Identifies functions marked for protection
 * 
 * Functions can be marked using:
 *   __attribute__((ironlock_protect))
 *   __declspec(ironlock_protect)
 */
class IronLockProtectionMarker : public llvm::FunctionPass {
public:
    static char ID;
    
    IronLockProtectionMarker() : llvm::FunctionPass(ID) {}
    
    bool runOnFunction(llvm::Function &F) override;
    void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
    
private:
    bool isMarkedForProtection(const llvm::Function &F);
    void addProtectionMetadata(llvm::Function &F);
};

/**
 * ControlFlowFlatteningPass - VMProtect-style CFF at IR level
 * 
 * Transforms function CFG into a state machine with:
 * - Dispatcher block
 * - Flattened basic blocks
 * - State variable tracking
 * - Bogus control flow edges
 */
class ControlFlowFlatteningPass : public llvm::FunctionPass {
public:
    static char ID;
    
    ControlFlowFlatteningPass();
    
    bool runOnFunction(llvm::Function &F) override;
    void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
    
private:
    struct FlattenState {
        llvm::AllocaInst *stateVar;
        llvm::BasicBlock *dispatcher;
        std::map<llvm::BasicBlock*, int> blockStates;
        int nextState;
    };
    
    bool flattenFunction(llvm::Function &F);
    FlattenState createDispatcher(llvm::Function &F);
    void redirectBlocks(llvm::Function &F, FlattenState &state);
    void insertOpaquePredicates(llvm::Function &F);
    llvm::Value *generateStateUpdate(llvm::Function &F, FlattenState &state, int newState);
};

/**
 * StringEncryptionPass - Compile-time string encryption
 * 
 * Encrypts all string constants in the module with AES-256
 * and inserts decryption stubs at usage sites.
 */
class StringEncryptionPass : public llvm::ModulePass {
public:
    static char ID;
    
    StringEncryptionPass();
    
    bool runOnModule(llvm::Module &M) override;
    
private:
    bool encryptStrings(llvm::Module &M);
    llvm::Function *createDecryptionStub(llvm::Module &M);
    void replaceStringUses(llvm::GlobalVariable *gv, llvm::Function *decryptStub);
};

/**
 * VirtualizationCandidatePass - Identifies functions suitable for VM protection
 * 
 * Analyzes functions and marks those that are good candidates for
 * full virtualization based on:
 * - Cyclomatic complexity
 * - Presence of security checks
 * - Lack of performance-critical loops
 */
class VirtualizationCandidatePass : public llvm::ModulePass {
public:
    static char ID;
    
    VirtualizationCandidatePass();
    
    bool runOnModule(llvm::Module &M) override;
    
private:
    bool analyzeFunction(llvm::Function &F);
    int calculateComplexity(llvm::Function &F);
    bool hasSecurityPatterns(llvm::Function &F);
    bool isPerformanceCritical(llvm::Function &F);
};

/**
 * OpaquePredicatePass - Inserts opaque predicates to confuse disassemblers
 * 
 * Adds always-true/false conditions that are hard to resolve statically
 * but trivial at runtime.
 */
class OpaquePredicatePass : public llvm::FunctionPass {
public:
    static char ID;
    
    OpaquePredicatePass();
    
    bool runOnFunction(llvm::Function &F) override;
    
private:
    void insertOpaquePredicates(llvm::Function &F);
    llvm::Value *createTruePredicate(llvm::IRBuilder<> &builder);
    llvm::Value *createFalsePredicate(llvm::IRBuilder<> &builder);
};

// Legacy pass manager registration
void registerIronLockPasses(const llvm::PassManagerBuilder &Builder,
                            llvm::legacy::PassManagerBase &PM);

} // namespace ironlock
