public class Heap {
    private final Object[] objects;
    private int index;

    public Heap(int size) {
        this.objects = new Object[size];
    }

    public int getIndex() {
        return index;
    }

    public void addObject(Object object) {
        objects[index++] = object;
    }

    public Object getObject(int index) {
        return objects[index];
    }
}
