/**
 * IronLock LLVM Plugin Implementation
 * 
 * Direct integration with LLVM/Clang compilation pipeline for IR-level protection.
 */

#include "IronLockLLVMPlugin.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/Crypto.h"
#include <random>
#include <set>

namespace llvm {
namespace cl {
    opt<bool> EnableCFF("ironlock-cff", desc("Enable Control Flow Flattening"), init(false));
    opt<bool> EnableVirtualization("ironlock-virt", desc("Enable function virtualization"), init(false));
    opt<bool> EnableStringEncryption("ironlock-strenc", desc("Enable string encryption"), init(true));
    opt<bool> EnableOpaquePredicates("ironlock-opaque", desc("Enable opaque predicates"), init(true));
    opt<std::string> ProtectionProfile("ironlock-profile", desc("Protection profile file"), init(""));
}
}

namespace ironlock {

using namespace llvm;

char IronLockProtectionMarker::ID = 0;
char ControlFlowFlatteningPass::ID = 0;
char StringEncryptionPass::ID = 0;
char VirtualizationCandidatePass::ID = 0;
char OpaquePredicatePass::ID = 0;

// ============================================================================
// IronLockProtectionMarker
// ============================================================================

bool IronLockProtectionMarker::isMarkedForProtection(const Function &F) {
    // Check for ironlock_protect attribute
    if (F.hasFnAttribute("ironlock_protect"))
        return true;
    
    // Check for declspec marker
    if (F.getName().contains(".ironlock"))
        return true;
    
    // Check via metadata
    if (auto *MD = F.getMetadata("ironlock"))
        return true;
    
    return false;
}

void IronLockProtectionMarker::addProtectionMetadata(Function &F) {
    LLVMContext &Ctx = F.getContext();
    
    // Add metadata to mark this function for later passes
    MDString *key = MDString::get(Ctx, "protection_level");
    MDString *value = MDString::get(Ctx, "full");
    
    SmallVector<Metadata *, 2> Ops;
    Ops.push_back(key);
    Ops.push_back(value);
    
    F.setMetadata("ironlock", MDNode::get(Ctx, Ops));
}

bool IronLockProtectionMarker::runOnFunction(Function &F) {
    if (F.isDeclaration() || F.empty())
        return false;
    
    if (isMarkedForProtection(F)) {
        addProtectionMetadata(F);
        return true;
    }
    
    return false;
}

void IronLockProtectionMarker::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesAll();
}

// ============================================================================
// ControlFlowFlatteningPass
// ============================================================================

ControlFlowFlatteningPass::ControlFlowFlatteningPass() : FunctionPass(ID) {}

bool ControlFlowFlatteningPass::flattenFunction(Function &F) {
    if (F.empty() || F.size() < 3)
        return false;
    
    FlattenState state;
    state.nextState = 0;
    
    // Create state variable (alloca in entry block)
    IRBuilder<> EntryBuilder(&F.getEntryBlock(), F.getEntryBlock().begin());
    Type *Int32Ty = Type::getInt32Ty(F.getContext());
    state.stateVar = EntryBuilder.CreateAlloca(Int32Ty, nullptr, "cff_state");
    EntryBuilder.CreateStore(ConstantInt::get(Int32Ty, 0), state.stateVar);
    
    // Assign state numbers to blocks
    for (auto &BB : F) {
        if (!BB.empty()) {
            state.blockStates[&BB] = state.nextState++;
        }
    }
    
    // Create dispatcher block
    createDispatcher(F, state);
    
    // Redirect control flow through dispatcher
    redirectBlocks(F, state);
    
    // Insert opaque predicates for additional confusion
    insertOpaquePredicates(F);
    
    return true;
}

ControlFlowFlatteningPass::FlattenState ControlFlowFlatteningPass::createDispatcher(Function &F) {
    FlattenState state;
    state.dispatcher = BasicBlock::Create(F.getContext(), "dispatcher", &F);
    
    IRBuilder<> DispBuilder(state.dispatcher);
    Type *Int32Ty = Type::getInt32Ty(F.getContext());
    
    // Load current state
    Value *currentState = DispBuilder.CreateLoad(Int32Ty, state.stateVar, "curr_state");
    
    // Create switch with all possible states
    SwitchInst *Switch = DispBuilder.CreateSwitch(
        currentState, 
        nullptr, 
        state.blockStates.size()
    );
    
    // Add cases for each block
    for (auto &[BB, stateNum] : state.blockStates) {
        Switch->addCase(ConstantInt::get(Int32Ty, stateNum), BB);
    }
    
    return state;
}

void ControlFlowFlatteningPass::redirectBlocks(Function &F, FlattenState &state) {
    Type *Int32Ty = Type::getInt32Ty(F.getContext());
    
    for (auto &BB : F) {
        if (&BB == state.dispatcher)
            continue;
        
        auto termInst = BB.getTerminator();
        if (!termInst)
            continue;
        
        if (auto *branch = dyn_cast<BranchInst>(termInst)) {
            if (branch->isUnconditional()) {
                // Replace unconditional branch with state update + jump to dispatcher
                IRBuilder<> Builder(termInst);
                
                // Find next block's state number
                auto nextBB = branch->getSuccessor(0);
                int nextState = state.blockStates[nextBB];
                
                // Update state
                Builder.CreateStore(ConstantInt::get(Int32Ty, nextState), state.stateVar);
                
                // Branch to dispatcher
                Builder.CreateBr(state.dispatcher);
                
                // Remove old terminator
                termInst->eraseFromParent();
            } else {
                // Conditional branch - more complex handling needed
                // For now, keep as-is but could be enhanced
            }
        }
    }
}

void ControlFlowFlatteningPass::insertOpaquePredicates(Function &F) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 100);
    
    for (auto &BB : F) {
        if (&BB == state.dispatcher || dis(gen) > 30)
            continue;
        
        // Insert opaque predicate at beginning of block
        IRBuilder<> Builder(&BB, BB.begin());
        
        // Create always-true condition using opaque math
        Value *opaque = createTruePredicate(Builder);
        
        // Create dead branch that's never taken
        BasicBlock *DeadBlock = BasicBlock::Create(F.getContext(), "dead_" + BB.getName(), &F);
        BasicBlock *ContinueBlock = BasicBlock::Create(F.getContext(), "cont_" + BB.getName(), &F);
        
        Builder.CreateCondBr(opaque, ContinueBlock, DeadBlock);
        
        // Move original instructions to ContinueBlock
        ContinueBlock->getInstList().splice(ContinueBlock->end(), BB.getInstList(), BB.begin(), BB.getFirstInsertionPt());
    }
}

Value* ControlFlowFlatteningPass::generateStateUpdate(Function &F, FlattenState &state, int newState) {
    IRBuilder<> Builder(state.dispatcher);
    Type *Int32Ty = Type::getInt32Ty(F.getContext());
    return Builder.CreateStore(ConstantInt::get(Int32Ty, newState), state.stateVar);
}

bool ControlFlowFlatteningPass::runOnFunction(Function &F) {
    if (!cl::EnableCFF)
        return false;
    
    return flattenFunction(F);
}

void ControlFlowFlatteningPass::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addPreserved<DominatorTreeWrapperPass>();
}

// ============================================================================
// StringEncryptionPass
// ============================================================================

StringEncryptionPass::StringEncryptionPass() : ModulePass(ID) {}

bool StringEncryptionPass::encryptStrings(Module &M) {
    bool Modified = false;
    
    // Collect all global strings
    SmallVector<GlobalVariable*, 8> StringGlobals;
    for (auto &GV : M.globals()) {
        if (GV.isConstant() && GV.hasInitializer()) {
            if (isa<ConstantDataSequential>(GV.getInitializer())) {
                StringGlobals.push_back(&GV);
            }
        }
    }
    
    if (StringGlobals.empty())
        return false;
    
    // Create decryption stub
    Function *DecryptStub = createDecryptionStub(M);
    
    // Encrypt each string
    for (auto *GV : StringGlobals) {
        replaceStringUses(GV, DecryptStub);
        Modified = true;
    }
    
    return Modified;
}

Function* StringEncryptionPass::createDecryptionStub(Module &M) {
    LLVMContext &Ctx = M.getContext();
    
    // Create decryption function signature: void*(i8*, i32, i8*)
    Type *PtrTy = PointerType::get(Ctx, 0);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    
    FunctionType *FTy = FunctionType::get(PtrTy, {PtrTy, Int32Ty, PtrTy}, false);
    Function *DecryptFunc = Function::Create(FTy, GlobalValue::InternalLinkage, "il_decrypt_str", &M);
    
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", DecryptFunc);
    IRBuilder<> Builder(Entry);
    
    // Get arguments
    auto Args = DecryptFunc->arg_begin();
    Value *EncryptedData = &*Args++;
    Value *Length = &*Args++;
    Value *Key = &*Args++;
    
    // Simple XOR decryption loop (in production, use AES)
    BasicBlock *LoopHead = BasicBlock::Create(Ctx, "loop", DecryptFunc);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "body", DecryptFunc);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", DecryptFunc);
    
    Builder.CreateBr(LoopHead);
    
    Builder.SetInsertPoint(LoopHead);
    PHINode *Index = Builder.CreatePHI(Int32Ty, 2, "i");
    Index->addIncoming(ConstantInt::get(Int32Ty, 0), Entry);
    
    Value *Cond = Builder.CreateICmpULT(Index, Length);
    Builder.CreateCondBr(Cond, LoopBody, Exit);
    
    Builder.SetInsertPoint(LoopBody);
    Value *KeyByte = Builder.CreateInBoundsGEP(Type::getInt8Ty(Ctx), Key, Index);
    Value *DataByte = Builder.CreateInBoundsGEP(Type::getInt8Ty(Ctx), EncryptedData, Index);
    Value *KVal = Builder.CreateLoad(Type::getInt8Ty(Ctx), KeyByte);
    Value *DVal = Builder.CreateLoad(Type::getInt8Ty(Ctx), DataByte);
    Value *XorVal = Builder.CreateXor(DVal, KVal);
    Builder.CreateStore(XorVal, DataByte);
    
    Value *NextIndex = Builder.CreateAdd(Index, ConstantInt::get(Int32Ty, 1));
    Index->addIncoming(NextIndex, LoopBody);
    Builder.CreateBr(LoopHead);
    
    Builder.SetInsertPoint(Exit);
    Builder.CreateRet(EncryptedData);
    
    return DecryptFunc;
}

void StringEncryptionPass::replaceStringUses(GlobalVariable *gv, Function *decryptStub) {
    // In production: encrypt the initializer and insert calls to decryptStub
    // This is a simplified version
    LLVMContext &Ctx = gv->getContext();
    
    // Mark for runtime decryption
    MDString *key = MDString::get(Ctx, "encrypted");
    MDString *value = MDString::get(Ctx, "aes256");
    SmallVector<Metadata *, 2> Ops = {key, value};
    gv->setMetadata("ironlock", MDNode::get(Ctx, Ops));
}

bool StringEncryptionPass::runOnModule(Module &M) {
    if (!cl::EnableStringEncryption)
        return false;
    
    return encryptStrings(M);
}

// ============================================================================
// VirtualizationCandidatePass
// ============================================================================

VirtualizationCandidatePass::VirtualizationCandidatePass() : ModulePass(ID) {}

int VirtualizationCandidatePass::calculateComplexity(Function &F) {
    int complexity = 1; // Base complexity
    
    // Count basic blocks (branches)
    complexity += F.size();
    
    // Count conditional branches
    for (auto &BB : F) {
        if (auto *term = BB.getTerminator()) {
            if (auto *branch = dyn_cast<BranchInst>(term)) {
                if (branch->isConditional())
                    complexity++;
            }
            if (isa<SwitchInst>(term))
                complexity += 2;
        }
    }
    
    return complexity;
}

bool VirtualizationCandidatePass::hasSecurityPatterns(Function &F) {
    // Look for security-related patterns
    for (auto &BB : F) {
        for (auto &I : BB) {
            if (auto *call = dyn_cast<CallInst>(&I)) {
                if (Function *Callee = call->getCalledFunction()) {
                    StringRef name = Callee->getName();
                    if (name.contains("check") || name.contains("verify") ||
                        name.contains("validate") || name.contains("auth"))
                        return true;
                }
            }
            
            // Look for comparison patterns common in license checks
            if (isa<CmpInst>(&I))
                return true;
        }
    }
    
    return false;
}

bool VirtualizationCandidatePass::isPerformanceCritical(Function &F) {
    // Heuristic: functions with tight loops are performance-critical
    for (auto &BB : F) {
        int loadCount = 0;
        int storeCount = 0;
        
        for (auto &I : BB) {
            if (isa<LoadInst>(&I)) loadCount++;
            if (isa<StoreInst>(&I)) storeCount++;
        }
        
        // High memory access ratio suggests performance-critical code
        if (loadCount > 10 && storeCount > 5)
            return true;
    }
    
    return false;
}

bool VirtualizationCandidatePass::analyzeFunction(Function &F) {
    if (F.isDeclaration() || F.empty())
        return false;
    
    int complexity = calculateComplexity(F);
    bool hasSecurity = hasSecurityPatterns(F);
    bool isPerfCritical = isPerformanceCritical(F);
    
    // Good candidates: medium-high complexity, security patterns, not perf-critical
    return (complexity >= 5 && hasSecurity && !isPerfCritical);
}

bool VirtualizationCandidatePass::runOnModule(Module &M) {
    if (!cl::EnableVirtualization)
        return false;
    
    bool Modified = false;
    
    for (auto &F : M.functions()) {
        if (analyzeFunction(F)) {
            // Mark for virtualization
            MDString *key = MDString::get(M.getContext(), "virtualize");
            MDString *value = MDString::get(M.getContext(), "true");
            SmallVector<Metadata *, 2> Ops = {key, value};
            F.setMetadata("ironlock", MDNode::get(M.getContext(), Ops));
            Modified = true;
        }
    }
    
    return Modified;
}

// ============================================================================
// OpaquePredicatePass
// ============================================================================

OpaquePredicatePass::OpaquePredicatePass() : FunctionPass(ID) {}

Value* OpaquePredicatePass::createTruePredicate(IRBuilder<> &builder) {
    // Create an opaque always-true predicate
    // (x * (x + 1)) is always even, so ((x * (x + 1)) % 2) == 0 is always true
    
    Type *Int32Ty = builder.getInt32Ty();
    
    // Use timestamp or random value to make it hard to predict statically
    Value *X = builder.CreateCall(
        Intrinsic::getDeclaration(builder.GetInsertBlock()->getModule()->getParent(),
                                  Intrinsic::rdtsc),
        {}
    );
    
    Value *XPlus1 = builder.CreateAdd(X, ConstantInt::get(Int32Ty, 1));
    Value *Product = builder.CreateMul(X, XPlus1);
    Value *Remainder = builder.CreateURem(Product, ConstantInt::get(Int32Ty, 2));
    
    return builder.CreateICmpEQ(Remainder, ConstantInt::get(Int32Ty, 0));
}

Value* OpaquePredicatePass::createFalsePredicate(IRBuilder<> &builder) {
    // Create an opaque always-false predicate
    Value *TruePred = createTruePredicate(builder);
    return builder.CreateNot(TruePred);
}

void OpaquePredicatePass::insertOpaquePredicates(Function &F) {
    if (!cl::EnableOpaquePredicates)
        return;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 100);
    
    for (auto &BB : F) {
        // Skip empty blocks and dispatcher
        if (BB.empty() || BB.getName().contains("dispatcher"))
            continue;
        
        // Randomly insert opaque predicates (30% chance per block)
        if (dis(gen) > 30)
            continue;
        
        IRBuilder<> Builder(&BB, BB.begin());
        
        // Create opaque condition
        Value *Condition = (dis(gen) > 50) ? createTruePredicate(Builder) : createFalsePredicate(Builder);
        
        // Create dead branch
        BasicBlock *DeadBlock = BasicBlock::Create(F.getContext(), "opaque_dead", &F);
        BasicBlock *OrigBlock = BasicBlock::Create(F.getContext(), "opaque_cont", &F);
        
        Builder.CreateCondBr(Condition, OrigBlock, DeadBlock);
        
        // Move original instructions to OrigBlock
        auto FirstInst = BB.getFirstInsertionPt();
        if (FirstInst != BB.end()) {
            OrigBlock->getInstList().splice(OrigBlock->end(), BB.getInstList(), 
                                            FirstInst, BB.end());
        }
        
        // Add unreachable to dead block
        Builder.SetInsertPoint(DeadBlock);
        Builder.CreateUnreachable();
        
        // Branch from OrigBlock back to continuation
        Builder.SetInsertPoint(OrigBlock);
        // Original instructions already moved
    }
}

bool OpaquePredicatePass::runOnFunction(Function &F) {
    insertOpaquePredicates(F);
    return true;
}

// ============================================================================
// Pass Registration
// ============================================================================

void registerIronLockPasses(const PassManagerBuilder &Builder,
                            legacy::PassManagerBase &PM) {
    PM.add(new IronLockProtectionMarker());
    PM.add(new ControlFlowFlatteningPass());
    PM.add(new StringEncryptionPass());
    PM.add(new VirtualizationCandidatePass());
    PM.add(new OpaquePredicatePass());
}

// Register with legacy pass manager
static RegisterStandardPasses RegisterCLPass(
    PassManagerBuilder::EP_OptimizerLast,
    registerIronLockPasses
);

} // namespace ironlock
