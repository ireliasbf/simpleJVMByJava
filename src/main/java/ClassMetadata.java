import java.util.LinkedHashMap;

public class ClassMetadata {
    private final String className;
    private final String superClassName;
    private final String[] interfaces;
    private final String[] constantPoolType;
    private final Object[] constantPool;
    private final int constantPoolCount;
    private final String[] filedsName;
    private final Object[] fields;
    private int fieldsSize;
    private final LinkedHashMap<String, Byte[]> methods;
    private final LinkedHashMap<String,Integer> methodsArgsNumbers;
    public ClassMetadata(String className, String superClassName, String[] interfaces,String[] constantPoolType,Object[] constantPool,String[] filedsName,Object[] fields, LinkedHashMap<String, Byte[]> methods, LinkedHashMap<String,Integer> methodsArgsNumbers) {
        this.className = className;
        this.superClassName = superClassName;
        this.interfaces = interfaces;
        this.constantPoolType = constantPoolType;
        this.constantPool = constantPool;
        this.constantPoolCount = constantPool.length;
        this.filedsName = filedsName;
        this.fields = fields;
        this.fieldsSize = fields.length;
        this.methods = methods;
        this.methodsArgsNumbers = methodsArgsNumbers;
    }

    public String[] getConstantPoolType() {
        return constantPoolType;
    }

    public Object[] getConstantPool() {
        return constantPool;
    }

    public int getConstantPoolCount() {
        return constantPoolCount;
    }


    public String[] getFiledsName() {
        return filedsName;
    }

    public Object[] getFields() {
        return fields;
    }

    public int getFieldsSize() {
        return fieldsSize;
    }

    public String getClassName() {
        return className;
    }

    public String getSuperClassName() {
        return superClassName;
    }

    public String[] getInterfaces() {
        return interfaces;
    }

    public LinkedHashMap<String, Byte[]> getMethods() {
        return methods;
    }

    public int getMethodArgsNumbers(String methodName) {
        return methodsArgsNumbers.get(methodName);
    }

    public void setMethodArgsNumbers(String methodName, int value) {
        methodsArgsNumbers.put(methodName, value);
    }
}
