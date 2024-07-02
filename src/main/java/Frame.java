public class Frame {
    private final Object[] locals;
    private int localIndex;
    private int operandStackIndex;
    private final Object[] operandStack;
    private final Object[] constantPool; // 常量池
    private int nextPc;
    public Frame(int localSize, int operandStackSize, int constantPoolSize) {
        this.locals = new Object[localSize];
        this.operandStack = new Object[operandStackSize];
        this.constantPool = new Object[constantPoolSize]; // 初始化常量池
    }

    public void setLocal(int index, Object value) {
        locals[index] = value;
    }

    public Object getLocal(int index) {
        return locals[index];
    }

    public void pushOperandStack(Object value) {
        operandStack[operandStackIndex++] = value;
    }

    public Object popOperandStack() {
        return operandStack[--operandStackIndex];
    }

    // 设置常量池中的值
    public void setConstant(int index, Object value) {
        constantPool[index] = value;
    }

    // 获取常量池中的值
    public Object getConstant(int index) {
        return constantPool[index];
    }

    public void setNextPc(int nextPc) {
        this.nextPc = nextPc;
    }

    public int getNextPc() {
        return nextPc;
    }
}