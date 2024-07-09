import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class MethodArea {
    private final Map<String, ClassMetadata> classMetadataMap;

    public MethodArea() {
        this.classMetadataMap = new HashMap<>();
    }

    public ClassMetadata createClassMetadata(String className, String superClassName, String[] interfaces,String[] constantPoolType,Object[] constantPool,String[] filedsName,Object[] fields, LinkedHashMap<String, Byte[]> methods, LinkedHashMap<String,Integer> methodsArgsNumbers){
        return new ClassMetadata(className, superClassName, interfaces,constantPoolType,constantPool,filedsName,fields, methods, methodsArgsNumbers);
    }

    public void loadClass(ClassMetadata classMetadata) {
        this.classMetadataMap.put(classMetadata.getClassName(), classMetadata);
    }

    public ClassMetadata getClassMetadata(String className) {
        return classMetadataMap.get(className);
    }
}

