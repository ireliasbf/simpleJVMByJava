public class MyClass {
    private String name;
    private final Object[] constantPool;
    private final Frame[] stack;
    public int sp = 0;

    public MyClass(String name, int constantPoolSize, int stackSize) {
        this.name = name;
        this.constantPool = new Object[constantPoolSize];
        this.stack = new Frame[stackSize];
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }


    public void setConstant(int index, Object value) {
        constantPool[index] = value;
    }

    // 获取常量池中的值
    public Object getConstant(int index) {
        return constantPool[index];
    }

    public void pushFrame(Frame frame) {
        stack[sp++] = frame;
    }

    public Frame popFrame() {
        return stack[--sp];
    }

    public Frame currentFrame() {
        return stack[sp - 1];
    }

}
