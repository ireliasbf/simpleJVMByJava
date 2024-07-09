public class Frame {
    private final Object[] locals;
    private int localIndex;
    private int operandStackIndex;
    private final Object[] operandStack;
    private int returnAddress;
    private String currentMethodIndex;

    public Frame(int localSize, int operandStackSize) {
        this.locals = new Object[localSize];
        this.operandStack = new Object[operandStackSize];
        this.operandStackIndex = 0;
    }

    public int getLocalIndex() {
        return localIndex;
    }

    public void setLocal(int index, Object value) {
        locals[index] = value;
        localIndex=Math.max(localIndex,index+1);
    }

    public Object getLocal(int index) {
        return locals[index];
    }

    public Boolean isStackEmpty() {
        return operandStackIndex == 0;
    }

    public void pushOperandStack(Object value) {
        operandStack[operandStackIndex++] = value;
    }

    public Object popOperandStack() {
        return operandStack[--operandStackIndex];
    }

    public void setReturnAddress(int returnAddress) {
        this.returnAddress = returnAddress;
    }

    public int getReturnAddress() {
        return returnAddress;
    }

    public void setCurrentMethodIndex(String currentMethodIndex) {
        this.currentMethodIndex = currentMethodIndex;
    }

    public String getCurrentMethodIndex() {
        return currentMethodIndex;
    }
}