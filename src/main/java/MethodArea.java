import java.util.HashMap;
import java.util.Map;

public class MethodArea {
    private final Map<String, ClassMetadata> classMetadataMap;

    public MethodArea() {
        this.classMetadataMap = new HashMap<>();
    }

    public ClassMetadata createClassMetadata(String className, String superClassName, String[] interfaces, Map<String, String> fields, Map<Integer, int[]> methods, int[] methodsArgsNumbers){
        return new ClassMetadata(className, superClassName, interfaces, fields, methods, methodsArgsNumbers);
    }

    public void loadClass(ClassMetadata classMetadata) {
        classMetadataMap.put(classMetadata.getClassName(), classMetadata);
    }

    public ClassMetadata getClassMetadata(String className) {
        return classMetadataMap.get(className);
    }
}

