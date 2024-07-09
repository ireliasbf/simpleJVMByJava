public class MyClass {
    private String name;
    private final String classname;
    private final String[] constantPoolType;
    private final Object[] constantPool;
    private int constantPoolCount = 0;
    private final Frame[] stack;
    private final String[] filedsName;
    private final Object[] fields;
    private int fieldsSize = 0;
    public int sp = 0;

    public MyClass(String name,String[] constantPoolType,Object[] constantPool,String[] filedsName,Object[] fields,int stackSize) {
        this.name = name;
        this.classname = name;
        this.constantPoolType = constantPoolType;
        this.constantPool = constantPool;
        this.stack = new Frame[stackSize];
        this.fields = fields;
        this.filedsName = filedsName;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String getClassname() {
        return classname;
    }

    public String[] getConstantPoolType() {
        return constantPoolType;
    }

    public String getConstantType(int index) {
        return constantPoolType[index];
    }

    public int getConstantPoolCount() {
        return constantPoolCount;
    }

    public void setConstant(int index, Object value) {
        constantPool[index] = value;
        constantPoolCount = Math.max(constantPoolCount, index + 1);
    }

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

    public void setField(String fieldName, Object value) {
        int index = 0;
        for(int i=0;i<fieldName.length();++i){
            if(this.filedsName[i].equals(fieldName)){
                index = i;
                break;
            }
        }
        fields[index] = value;
        fieldsSize = Math.max(fieldsSize, index + 1);
    }

    public Object getField(int index) {
        return fields[index];
    }

    public int getFieldsSize() {
        return fieldsSize;
    }

}
