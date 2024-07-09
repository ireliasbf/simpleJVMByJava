public class Heap {
    private final MyClass[] myClasses;
    private int index;

    public Heap(int size) {
        this.myClasses = new MyClass[size];
        this.index = -1;
    }

    public int getIndex() {
        return index;
    }

    public void addObject(MyClass object) {
        myClasses[++index] = object;
    }

    public MyClass getObject(int index) {
        return myClasses[index];
    }
}
