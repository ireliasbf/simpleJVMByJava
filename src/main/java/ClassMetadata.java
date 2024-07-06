import java.util.Map;

public class ClassMetadata {
    private final String className;
    private final String superClassName;
    private final String[] interfaces;
    private final Map<String, String> fields;
    private final Map<Integer, int[]> methods;
    private final int[] methodsArgsNumbers;
    public ClassMetadata(String className, String superClassName, String[] interfaces, Map<String, String> fields, Map<Integer, int[]> methods, int[] methodsArgsNumbers) {
        this.className = className;
        this.superClassName = superClassName;
        this.interfaces = interfaces;
        this.fields = fields;
        this.methods = methods;
        this.methodsArgsNumbers = methodsArgsNumbers;
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

    public Map<String, String> getFields() {
        return fields;
    }

    public Map<Integer, int[]> getMethods() {
        return methods;
    }

    public int getMethodArgsNumbers(int index) {
        return methodsArgsNumbers[index];
    }
}
