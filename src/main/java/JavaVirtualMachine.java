import org.jetbrains.annotations.NotNull;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

public class JavaVirtualMachine {
    String[] instructionNames = {
            "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "lconst_0",
            "lconst_1", "fconst_0", "fconst_1", "fconst_2", "dconst_0", "dconst_1", "bipush", "sipush", "ldc", "ldc_w",
            "ldc2_w", "iload", "lload", "fload", "dload", "aload", "iload_0", "iload_1", "iload_2", "iload_3",
            "lload_0", "lload_1", "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3", "dload_0", "dload_1",
            "dload_2", "dload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "laload", "faload", "daload",
            "aaload", "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore", "astore", "istore_0",
            "istore_1", "istore_2", "istore_3", "lstore_0", "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2",
            "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore",
            "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup",
            "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap", "iadd", "ladd", "fadd", "dadd",
            "isub", "lsub", "fsub", "dsub", "imul", "lmul", "fmul", "dmul", "idiv", "ldiv",
            "fdiv", "ddiv", "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg",
            "ishl", "lshl", "ishr", "lshr", "iushr", "lushr", "iand", "land", "ior", "lor",
            "ixor", "lxor", "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i",
            "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl",
            "fcmpg", "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq",
            "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret",
            "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return", "getstatic", "putstatic",
            "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic", "new", "newarray", "anewarray",
            "arraylength", "athrow", "checkcast", "instanceof", "monitorenter", "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull",
            "goto_w", "jsr_w"
    };

    static int pc = 0;
    static Byte[] Opcodes;
    static Frame frame;
    static MethodArea methodArea = new MethodArea();
    static Heap heap = new Heap(100);
    static MyClass myClass;

    static int print = 0;


    static int fetch() {
        if (print > 0)
            System.out.print(" " + Opcodes[pc]);
        print++;
        return Opcodes[pc++];
    }

    static int getOffset() {
        int bite_1 = fetch();
        int bite_2 = fetch();
        return (bite_1 << 8) | bite_2;
    }

    public enum Instructions {
        Nop {
            @Override
            public void execute(@NotNull MyClass myClass) {
                // do nothing
            }
        },
        Aconst_null {
            @Override
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(null);
            }
        },
        Iconst_m1 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(-1);
            }
        },
        Iconst_0 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(0);
            }
        },
        Iconst_1 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(1);
            }
        },
        Iconst_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(2);
            }
        },
        Iconst_3 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(3);
            }
        },
        Iconst_4 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(4);
            }
        },
        Iconst_5 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(5);
            }
        },
        Lconst_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(0L);
            }
        },
        Lconst_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(1L);
            }
        },
        Fconst_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(0.0f);
            }
        },
        Fconst_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(1.0f);
            }
        },
        Fconst_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(2.0f);
            }
        },
        Dconst_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(0.0);
            }
        },
        Dconst_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(1.0);
            }
        },
        Bipush {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(fetch());
            }
        },
        Sipush {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int bite_1 = fetch();
                int bite_2 = fetch();
                int combined = (bite_1 << 8) | bite_2;
                myClass.currentFrame().pushOperandStack(combined);
            }
        },
        Ldc {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index=fetch();
                if(myClass.getConstantType(index).equals("Integer"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
                else if(myClass.getConstantType(index).equals("Float"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
                else if(myClass.getConstantType(index).equals("String"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant((int)myClass.getConstant(index)));
            }
        },
        Ldc_w {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index_1=fetch();
                int index_2=fetch();
                int index=(index_1<<8)|index_2;
                if(myClass.getConstantType(index).equals("Integer"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
                else if(myClass.getConstantType(index).equals("Float"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
                else if(myClass.getConstantType(index).equals("String"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant((int)myClass.getConstant(index)));
            }
        },
        Ldc2_w {
            public void execute(@NotNull MyClass myClass) {
                int index_1=fetch();
                int index_2=fetch();
                int index=(index_1<<8)|index_2;
                if(myClass.getConstantType(index).equals("Long"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
                else if(myClass.getConstantType(index).equals("Double"))
                    myClass.currentFrame().pushOperandStack(myClass.getConstant(index));
            }
        },
        Iload {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(fetch()));
            }
        },
        Lload {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(fetch()));
            }
        },
        Fload {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(fetch()));
            }
        },
        Dload {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(fetch()));
            }
        },
        Aload {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(fetch()));
            }
        },
        Iload_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(0));
            }
        },
        Iload_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(1));
            }
        },
        Iload_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(2));
            }
        },
        Iload_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(3));
            }
        },
        Lload_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(0));
            }
        },
        Lload_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(1));
            }
        },
        Lload_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(2));
            }
        },
        Lload_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(3));
            }
        },
        Fload_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(0));
            }
        },
        Fload_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(1));
            }
        },
        Fload_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(2));
            }
        },
        Fload_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(3));
            }
        },
        Dload_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(0));
            }
        },
        Dload_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(1));
            }
        },
        Dload_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(2));
            }
        },
        Dload_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(3));
            }
        },
        Aload_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(0));
            }
        },
        Aload_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(1));
            }
        },
        Aload_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(2));
            }
        },
        Aload_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(myClass.currentFrame().getLocal(3));
            }
        },
        Iaload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                int[] array = (int[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Laload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                long[] array = (long[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Faload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                float[] array = (float[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Daload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                double[] array = (double[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Aaload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                Object[] array = (Object[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Baload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                byte[] array = (byte[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Caload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                char[] array = (char[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Saload {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = (int) myClass.currentFrame().popOperandStack();
                short[] array = (short[]) myClass.currentFrame().popOperandStack();
                myClass.currentFrame().pushOperandStack(array[index]);
            }
        },
        Istore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                myClass.currentFrame().setLocal(index, myClass.currentFrame().popOperandStack());
            }
        },
        Lstore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                myClass.currentFrame().setLocal(index, myClass.currentFrame().popOperandStack());
            }
        },
        Fstore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                myClass.currentFrame().setLocal(index, myClass.currentFrame().popOperandStack());
            }
        },
        Dstore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                myClass.currentFrame().setLocal(index, frame.popOperandStack());
            }
        },
        Astore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Istore_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(0, frame.popOperandStack());
            }
        },
        Istore_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(1, frame.popOperandStack());
            }
        },
        Istore_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(2, frame.popOperandStack());
            }
        },
        Istore_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(3, frame.popOperandStack());
            }
        },
        Lstore_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(0, frame.popOperandStack());
            }
        },
        Lstore_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(1, frame.popOperandStack());
            }
        },
        Lstore_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(2, frame.popOperandStack());
            }
        },
        Lstore_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(3, frame.popOperandStack());
            }
        },
        Fstore_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(0, frame.popOperandStack());
            }
        },
        Fstore_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(1, frame.popOperandStack());
            }
        },
        Fstore_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(2, frame.popOperandStack());
            }
        },
        Fstore_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(3, frame.popOperandStack());
            }
        },
        Dstore_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(0, frame.popOperandStack());
            }
        },
        Dstore_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(1, frame.popOperandStack());
            }
        },
        Dstore_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(2, frame.popOperandStack());
            }
        },
        Dstore_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(3, frame.popOperandStack());
            }
        },
        Astore_0 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(0, frame.popOperandStack());
            }
        },
        Astore_1 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(1, frame.popOperandStack());
            }
        },
        Astore_2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(2, frame.popOperandStack());
            }
        },
        Astore_3 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().setLocal(3, frame.popOperandStack());
            }
        },
        Iastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value = (int) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                int[] array = (int[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Lastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value = (long) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                long[] array = (long[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Fastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value = (float) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                float[] array = (float[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Dastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value = (double) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                double[] array = (double[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Aastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value = frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                Object[] array = (Object[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Bastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                byte value = (byte) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                byte[] array = (byte[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Castore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                char value = (char) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                char[] array = (char[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Sastore {
            @Override
            public void execute(@NotNull MyClass myClass) {
                short value = (short) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                short[] array = (short[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Pop {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().popOperandStack();
            }
        },
        Pop2 {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().popOperandStack();
                frame.popOperandStack();
            }
        },
        Dup {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value = frame.popOperandStack();
                frame.pushOperandStack(value);
                frame.pushOperandStack(value);
            }
        },
        Dup_X1 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup_X2 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                Object value3 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value3);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup2 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup2_X1 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                Object value3 = frame.popOperandStack();
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value3);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup2_X2 {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                Object value3 = frame.popOperandStack();
                Object value4 = frame.popOperandStack();
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value4);
                frame.pushOperandStack(value3);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Swap {
            @Override
            public void execute(@NotNull MyClass myClass) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
            }
        },
        Iadd {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Ladd {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Fadd {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Dadd {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Isub {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Lsub {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Fsub {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Dsub {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Imul {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Lmul {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Fmul {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Dmul {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Idiv {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Ldiv {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Fdiv {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Ddiv {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Irem {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Lrem {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Frem {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Drem {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Ineg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value = (int) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Lneg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value = (long) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Fneg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value = (float) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Dneg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value = (double) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Ishl {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 << value2);
            }
        },
        Lshl {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 << value2);
            }
        },
        Ishr {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >> value2);
            }
        },
        Lshr {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >> value2);
            }
        },
        Iushr {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >>> value2);
            }
        },
        Lushr {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >>> value2);
            }
        },
        Iand {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 & value2);
            }
        },
        Land {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 & value2);
            }
        },
        Ior {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 | value2);
            }
        },
        Lor {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 | value2);
            }
        },
        Ixor {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 ^ value2);
            }
        },
        Lxor {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 ^ value2);
            }
        },
        Iinc {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = fetch();
                int value = fetch();
                frame.setLocal(index, (int) frame.getLocal(index) + value);
            }
        },
        I2l {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((long) (int) frame.popOperandStack());
            }
        },
        I2f {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((float) (int) frame.popOperandStack());
            }
        },
        I2d {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((double) (int) frame.popOperandStack());
            }
        },
        L2i {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((int) (long) frame.popOperandStack());
            }
        },
        L2f {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((float) (long) frame.popOperandStack());
            }
        },
        L2d {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((double) (long) frame.popOperandStack());
            }
        },
        F2i {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((int) (float) frame.popOperandStack());
            }
        },
        F2l {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((long) (float) frame.popOperandStack());
            }
        },
        F2d {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((double) (float) frame.popOperandStack());
            }
        },
        D2i {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((int) (double) frame.popOperandStack());
            }
        },
        D2l {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((long) (double) frame.popOperandStack());
            }
        },
        D2f {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((float) (double) frame.popOperandStack());
            }
        },
        I2b {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((byte) (int) frame.popOperandStack());
            }
        },
        I2c {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((char) (int) frame.popOperandStack());
            }
        },
        I2s {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack((short) (int) frame.popOperandStack());
            }
        },
        Lcmp {
            @Override
            public void execute(@NotNull MyClass myClass) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                if (value1 > value2) {
                    frame.pushOperandStack(1);
                } else if (value1 == value2) {
                    frame.pushOperandStack(0);
                } else {
                    frame.pushOperandStack(-1);
                }
            }
        },
        Fcmpl {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                if (value1 > value2) {
                    frame.pushOperandStack(1);
                } else if (value1 == value2) {
                    frame.pushOperandStack(0);
                } else {
                    frame.pushOperandStack(-1);
                }
            }
        },
        Fcmpg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                if (value1 > value2) {
                    frame.pushOperandStack(1);
                } else if (value1 == value2) {
                    frame.pushOperandStack(0);
                } else {
                    frame.pushOperandStack(-1);
                }
            }
        },
        Dcmpl {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                if (value1 > value2) {
                    frame.pushOperandStack(1);
                } else if (value1 == value2) {
                    frame.pushOperandStack(0);
                } else {
                    frame.pushOperandStack(-1);
                }
            }
        },
        Dcmpg {
            @Override
            public void execute(@NotNull MyClass myClass) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                if (value1 > value2) {
                    frame.pushOperandStack(1);
                } else if (value1 == value2) {
                    frame.pushOperandStack(0);
                } else {
                    frame.pushOperandStack(-1);
                }
            }
        },
        Ifeq {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value == 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifne {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value != 0) {
                    pc += offset - 3;
                }
            }
        },
        Iflt {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value < 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifge {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value >= 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifgt {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value > 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifle {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value = (int) frame.popOperandStack();
                if (value <= 0) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpeq {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 == value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpne {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 != value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmplt {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 < value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpge {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 >= value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpgt {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 > value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmple {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 <= value2) {
                    pc += offset - 3;
                }
            }
        },
        If_acmpeq {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                if (value1 == value2) {
                    pc += offset - 3;
                }
            }
        },
        If_acmpne {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                if (value1 != value2) {
                    pc += offset - 3;
                }
            }
        },
        Goto {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int offset = getOffset();
                pc += offset - 3;
            }
        },
        Jsr {
            public void execute(@NotNull MyClass myClass) {
                myClass.currentFrame().pushOperandStack(pc);
                pc += fetch();
            }
        },
        Ret {
            @Override
            public void execute(@NotNull MyClass myClass) {
                pc = (int) frame.getLocal(fetch());
            }
        },
        Tableswitch {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = pc;
                while (index % 4 != 0) {
                    index++;
                }
                int defaultOffset = fetch();
                int low = fetch();
                int high = fetch();
                int[] offsets = new int[high - low + 1];
                for (int i = 0; i < offsets.length; i++) {
                    offsets[i] = fetch();
                }
                int key = (int) frame.popOperandStack();
                if (key < low || key > high) {
                    pc += defaultOffset;
                } else {
                    pc += offsets[key - low];
                }
            }
        },
        Lookupswitch {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int index = pc;
                while (index % 4 != 0) {
                    index++;
                }
                int defaultOffset = fetch();
                int npairs = fetch();
                Map<Integer, Integer> pairs = new HashMap<>();
                for (int i = 0; i < npairs; i++) {
                    int key = fetch();
                    int offset = fetch();
                    pairs.put(key, offset);
                }
                int key = (int) frame.popOperandStack();
                pc += pairs.getOrDefault(key, defaultOffset);
            }
        },
        Ireturn {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int value = (int) frame.popOperandStack();
                pc=frame.getReturnAddress();
                myClass.popFrame();
                frame = myClass.currentFrame();
                frame.pushOperandStack(value);
                Opcodes=methodArea.getClassMetadata(myClass.getClassname()).getMethods().get(frame.getCurrentMethodIndex());
            }
        },
        Lreturn {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Freturn {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Dreturn {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Areturn {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Return {
            @Override
            public void execute(@NotNull MyClass myClass) {
                pc=frame.getReturnAddress();
                if(myClass.sp>1)
                    myClass.popFrame();
                else{
                    pc=Opcodes.length;
                    return;
                }
                frame = myClass.currentFrame();
                Opcodes=methodArea.getClassMetadata(myClass.getClassname()).getMethods().get(frame.getCurrentMethodIndex());
            }
        },
        Getstatic {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Putstatic {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Getfield {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Putfield {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int address_1=fetch();
                int address_2=fetch();
                int address = (address_1 << 8) + address_2;
                Object value = myClass.currentFrame().popOperandStack();
                Object object = myClass.currentFrame().popOperandStack();
                MyClass currentClass=(MyClass)myClass.currentFrame().getLocal(0);
                int[] fieldRef=(int[])currentClass.getConstant(address);
                int[] fieldNameAndTypeIndex=(int[])currentClass.getConstant(fieldRef[1]);
                int fieldNameIndex=fieldNameAndTypeIndex[0];
                String fieldName=currentClass.getConstant(fieldNameIndex).toString();
                ((MyClass)object).setField(fieldName, value);
            }
        },
        Invokevirtual {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int address_1=fetch();
                int address_2=fetch();
                int address = (address_1 << 8) + address_2;
                int[] methodRef=(int[])myClass.getConstant(address);
                int classRefIndex=methodRef[0];
                int classNameIndex=(int)myClass.getConstant(classRefIndex);
                String className=myClass.getConstant(classNameIndex).toString();
                if(className.equals("java/lang/Object"))
                    return;
                ClassMetadata classMetadata = methodArea.getClassMetadata(className);
                int methodNameAndTypeIndex=methodRef[1];
                int[] methodNameAndType=(int[])myClass.getConstant(methodNameAndTypeIndex);
                int methodNameIndex=methodNameAndType[0];
                String methodName=myClass.getConstant(methodNameIndex).toString();
                Frame newFrame = new Frame(100,100);
                int argsCount=classMetadata.getMethodArgsNumbers(methodName);
                while(argsCount>0){
                    argsCount--;
                    newFrame.setLocal(argsCount+1,myClass.currentFrame().popOperandStack());
                }
                MyClass newClass=(MyClass)myClass.currentFrame().popOperandStack();
                newFrame.setLocal(0,newClass);
                newFrame.setReturnAddress(pc);
                newFrame.setCurrentMethodIndex(methodName);
                pc=0;
                Opcodes=classMetadata.getMethods().get(methodName);
                int argsNumber = classMetadata.getMethodArgsNumbers(methodName);
                while(!myClass.currentFrame().isStackEmpty()&&argsNumber>0){
                    argsNumber--;
                    newFrame.setLocal(argsNumber, myClass.currentFrame().popOperandStack());
                }
                myClass.pushFrame(newFrame);
                frame = myClass.currentFrame();
            }
        },
        Invokespecial {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int address_1=fetch();
                int address_2=fetch();
                int address = (address_1 << 8) + address_2;
                int[] methodRef=(int[])myClass.getConstant(address);
                int classRefIndex=methodRef[0];
                int classNameIndex=(int)myClass.getConstant(classRefIndex);
                String className=myClass.getConstant(classNameIndex).toString();
                if(className.equals("java/lang/Object"))
                    return;
                ClassMetadata classMetadata = methodArea.getClassMetadata(className);
                int methodNameAndTypeIndex=methodRef[1];
                int[] methodNameAndType=(int[])myClass.getConstant(methodNameAndTypeIndex);
                int methodNameIndex=methodNameAndType[0];
                String methodName=myClass.getConstant(methodNameIndex).toString();
                Frame newFrame = new Frame(100,100);
                MyClass newClass=(MyClass)myClass.currentFrame().popOperandStack();
                newFrame.setLocal(0,newClass);
                newFrame.setReturnAddress(pc);
                newFrame.setCurrentMethodIndex(methodName);
                pc=0;
                Opcodes=classMetadata.getMethods().get(methodName);
                int argsNumber = classMetadata.getMethodArgsNumbers(methodName);
                while(!myClass.currentFrame().isStackEmpty()&&argsNumber>0){
                    argsNumber--;
                    newFrame.setLocal(argsNumber, myClass.currentFrame().popOperandStack());
                }
                myClass.pushFrame(newFrame);
                frame = myClass.currentFrame();
            }
        },
        Invokestatic {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int address_1=fetch();
                int address_2=fetch();
                int address = (address_1 << 8) + address_2;
                Frame newFrame = new Frame(100,100);
                newFrame.setLocal(0,myClass);
                newFrame.setReturnAddress(pc);
                int[] methodRef=(int[])myClass.getConstant(address);
                int classRefIndex=methodRef[0];
                int classNameIndex=(int)myClass.getConstant(classRefIndex);
                String className=myClass.getConstant(classNameIndex).toString();
                if(className.equals("java/lang/Object"))
                    return;
                ClassMetadata classMetadata = methodArea.getClassMetadata(className);
                int methodNameAndTypeIndex=methodRef[1];
                int[] methodNameAndType=(int[])myClass.getConstant(methodNameAndTypeIndex);
                int methodNameIndex=methodNameAndType[0];
                String methodName=myClass.getConstant(methodNameIndex).toString();
                newFrame.setCurrentMethodIndex(methodName);
                pc=0;
                Opcodes=classMetadata.getMethods().get(methodName);
                int argsNumber = classMetadata.getMethodArgsNumbers(methodName);
                while(!myClass.currentFrame().isStackEmpty()&&argsNumber>0){
                    argsNumber--;
                    newFrame.setLocal(argsNumber, myClass.currentFrame().popOperandStack());
                }
                myClass.pushFrame(newFrame);
                frame = myClass.currentFrame();
            }
        },
        Invokeinterface {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Invokedynamic {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        New {
            @Override
            public void execute(@NotNull MyClass myClass) {
                int address_1=fetch();
                int address_2=fetch();
                int address = (address_1 << 8) + address_2;
                int classNameIndex=(int)myClass.getConstant(address);
                ClassMetadata classMetadata = methodArea.getClassMetadata(myClass.getConstant(classNameIndex).toString());
                MyClass newClass = new MyClass(classMetadata.getClassName(),classMetadata.getConstantPoolType(),classMetadata.getConstantPool(),classMetadata.getFiledsName(),classMetadata.getFields(),100);
                heap.addObject(newClass);
                myClass.currentFrame().pushOperandStack(newClass);
            }
        },
        Newarray {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Anewarray {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Arraylength {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Athrow {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Checkcast {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Instanceof {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Monitorenter {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Monitorexit {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Wide {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Multianewarray {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Ifnull {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Ifnonnull {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Goto_w {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        },
        Jsr_w {
            @Override
            public void execute(@NotNull MyClass myClass) {
                //do nothing
            }
        };

        public abstract void execute(MyClass myClass);
    }


    void eval(int opcode) {
        Instructions instruction = Instructions.values()[opcode&0xff];
        instruction.execute(myClass);
        System.out.println();
        print = 0;
    }

    public static int getParameterCountFromDescriptor(String descriptor) {
        int index = descriptor.indexOf(')');
        String parameters = descriptor.substring(1, index);

        int count = 0;
        int i = 0;
        while (i < parameters.length()) {
            char c = parameters.charAt(i);
            if (c == 'L') {
                // 对于类类型，需要找到';'的位置
                i = parameters.indexOf(';', i);
            } else if (c == '[') {
                // 对于数组类型，需要找到非'['的位置
                while (parameters.charAt(i) == '[') {
                    i++;
                }
                if (parameters.charAt(i) == 'L') {
                    i = parameters.indexOf(';', i);
                }
            }
            count++;
            i++;
        }
        return count;
    }

    Boolean loadClass(byte[] classData){
        //读取魔数
        int cur=0;
        int magic = ((classData[0] & 0xff) << 24) | ((classData[1] & 0xff) << 16) | ((classData[2] & 0xff) << 8) | (classData[3] & 0xff);
        cur+=4;
        if (magic != 0xCAFEBABE) {
            System.out.println("Not a java class file");
            return false;
        }
        //读取次版本号
        int minorVersion = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        //读取主版本号
        int majorVersion = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        //读取常量池
        int constantPoolCount = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        Object[] constantPool = new Object[constantPoolCount];
        String[] constantPoolType = new String[constantPoolCount];
        for (int i = 1; i < constantPoolCount; i++) {
            int tag = classData[cur++] & 0xff;
            switch (tag) {
                case 1:
                    constantPoolType[i] = "Utf8";
                    int length = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur+=2;
                    constantPool[i] = new String(classData, cur, length);
                    cur+=length;
                    break;
                case 3:
                    constantPoolType[i] = "Integer";
                    int value = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = value;
                    cur+=4;
                    break;
                case 4:
                    constantPoolType[i] = "Float";
                    int floatBits = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = Float.intBitsToFloat(floatBits);
                    cur+=4;
                    break;
                case 5:
                    constantPoolType[i] = "Long";
                    long value1 = ((long) (classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    long value2 = ((long) (classData[cur + 4] & 0xff) << 24) | ((classData[cur + 5] & 0xff) << 16) | ((classData[cur + 6] & 0xff) << 8) | (classData[cur + 7] & 0xff);
                    constantPool[i] = (value1 << 32) | value2;
                    cur+=8;
                    i++;
                    break;
                case 6:
                    constantPoolType[i] = "Double";
                    long longBits = ((long) (classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = Double.longBitsToDouble(longBits);
                    cur+=2;
                    break;
                case 7:
                    constantPoolType[i] = "Class";
                    int index = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur+=2;
                    constantPool[i] = index;
                    break;
                case 8:
                    constantPoolType[i] = "String";
                    int stringIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    constantPool[i] = stringIndex;
                    cur+=2;
                    break;
                case 9:
                    constantPoolType[i] = "Fieldref";
                    int classIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    int nameAndTypeIndex = ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = new int[]{classIndex, nameAndTypeIndex};
                    cur+=4;
                    break;
                case 10:
                    constantPoolType[i] = "Methodref";
                    int classIndex1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    int nameAndTypeIndex1 = ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = new int[]{classIndex1, nameAndTypeIndex1};
                    cur+=4;
                    break;
                case 11:
                    constantPoolType[i] = "InterfaceMethodref";
                    int classIndex2 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    int nameAndTypeIndex2 = ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = new int[]{classIndex2, nameAndTypeIndex2};
                    cur+=4;
                    break;
                case 12:
                    constantPoolType[i] = "NameAndType";
                    int nameIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    int descriptorIndex = ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = new int[]{nameIndex, descriptorIndex};
                    cur+=4;
                    break;
                case 15:
                    constantPoolType[i] = "MethodHandle";
                    int referenceKind = classData[cur++] & 0xff;
                    int referenceIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    constantPool[i] = new int[]{referenceKind, referenceIndex};
                    cur+=3;
                    break;
                case 16:
                    constantPoolType[i] = "MethodType";
                    int descriptorIndex1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    constantPool[i] = descriptorIndex1;
                    cur+=2;
                    break;
                case 18:
                    constantPoolType[i] = "InvokeDynamic";
                    int bootstrapMethodAttrIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    int nameAndTypeIndex3 = ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    constantPool[i] = new int[]{bootstrapMethodAttrIndex, nameAndTypeIndex3};
                    cur+=4;
                    break;
                case 19:
                    constantPoolType[i] = "Module";
                    int moduleNameIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    constantPool[i] = moduleNameIndex;
                    cur+=2;
                    break;
                case 20:
                    constantPoolType[i] = "Package";
                    int packageNameIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    constantPool[i] = packageNameIndex;
                    cur+=2;
                    break;
                default:
                    break;
            }
        }
        //读取访问标志
        int accessFlags = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        //读取类名
        int thisClass = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        String className = constantPool[(int)constantPool[thisClass]].toString();
        //读取父类名
        int superClass = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        String superClassName;
        if (superClass != 0) { // 对于Object类，没有父类
            superClassName = constantPool[(int)constantPool[superClass]].toString();
        } else {
            superClassName = null;
        }
        //读取接口
        int interfacesCount = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        String[] interfaces = new String[interfacesCount];
        for (int i = 0; i < interfacesCount; i++) {
            int index = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            interfaces[i] = constantPool[Integer.parseInt((String)constantPool[index])].toString();
            cur+=2;
        }
        //读取字段
        int fieldsCount = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        String[] fieldsName = new String[fieldsCount];
        Object[] fields = new Object[fieldsCount];
        cur+=2;
        for (int i = 0; i < fieldsCount; i++) {
            int accessFlags1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur+=2;
            int nameIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            fieldsName[i] = constantPool[nameIndex].toString();
            cur+=2;
            int descriptorIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur+=2;
            int attributesCount = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur+=2;
            for (int j = 0; j < attributesCount; j++) {
                int attributeNameIndex = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                cur+=2;
                int attributesLength = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                cur+=4;
                cur+=attributesLength;
            }
        }
        //读取方法
        int methodsCount = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        LinkedHashMap<String, Byte[]> methods = new LinkedHashMap<>();
        LinkedHashMap<String,Integer> methodsArgsNumbers = new LinkedHashMap<>();
        cur+=2;
        for (int i = 0; i < methodsCount; i++) {
            int accessFlags2 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur += 2;
            int nameIndex1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            String methodName = constantPool[nameIndex1].toString();
            cur += 2;
            int descriptorIndex1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            String descriptor = constantPool[descriptorIndex1].toString();
            int parameterCount = getParameterCountFromDescriptor(descriptor);
            cur += 2;
            int attributesCount1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur += 2;
            Byte[] code = null;
            for (int j = 0; j < attributesCount1; j++) {
                int attributeNameIndex1 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                cur += 2;
                int attributesLength1 = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                cur += 4;
                if (constantPool[attributeNameIndex1].toString().equals("Code")) {
                    int maxStack = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur += 2;
                    int maxLocals = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur += 2;
                    int codeLength = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                    cur += 4;
                    code = new Byte[codeLength];
                    for (int k = 0; k < codeLength; k++) {
                        code[k] = classData[cur++];
                    }
                    int exceptionTableLength = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur += 2;
                    for (int k = 0; k < exceptionTableLength; k++) {
                        int startPc = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                        cur += 2;
                        int endPc = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                        cur += 2;
                        int handlerPc = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                        cur += 2;
                        int catchType = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                        cur += 2;
                    }
                    int attributesCount2 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                    cur += 2;
                    for (int k = 0; k < attributesCount2; k++) {
                        int attributeNameIndex2 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
                        cur += 2;
                        int attributesLength2 = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
                        cur += 4;
                        cur += attributesLength2;
                    }
                }
                else {
                    cur += attributesLength1;
                }
            }
            methods.put(methodName, code);
            methodsArgsNumbers.put(methodName, parameterCount);
        }
        //读取属性
        int attributesCount2 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
        cur+=2;
        for (int i = 0; i < attributesCount2; i++) {
            int attributeNameIndex3 = ((classData[cur] & 0xff) << 8) | (classData[cur + 1] & 0xff);
            cur+=2;
            int attributesLength3 = ((classData[cur] & 0xff) << 24) | ((classData[cur + 1] & 0xff) << 16) | ((classData[cur + 2] & 0xff) << 8) | (classData[cur + 3] & 0xff);
            cur+=4;
            cur+=attributesLength3;
        }
        //创建类元数据
        methodArea.loadClass(methodArea.createClassMetadata(className, superClassName, interfaces,constantPoolType,constantPool,fieldsName,fields, methods, methodsArgsNumbers));
        return true;
    }

    Boolean loadFile(String directoryPath){
        //在指定路径下搜索class文件
        List<Exception> exceptions = new ArrayList<>();
        try{
            Stream<Path> paths = Files.walk(Paths.get(directoryPath));
            paths.filter(Files::isRegularFile).filter(path -> path.toString().endsWith(".class")).forEach(path -> {
                try {
                    System.out.println(path);
                    byte[] fileContent = Files.readAllBytes(path); // 读取文件内容
                    for(int i=0;i<fileContent.length;++i){
                        if(fileContent[i]==-1){
                            fileContent[i]=0x00;
                        }
                    }
                    if(!loadClass(fileContent)){
                        exceptions.add(new Exception("Failed to load class from file: " + path));
                    }
                } catch (IOException e) {
                    exceptions.add(e);
                }
            });
        } catch (IOException e) {
            exceptions.add(e);
        }
        exceptions.forEach(Exception::printStackTrace);
        return exceptions.isEmpty();
    }

    void run(String directoryPath) {
        if(!loadFile(directoryPath)) {
            System.out.println("Failed to load class files");
            return;
        }
        ClassMetadata mainClass= methodArea.getClassMetadata("Main");
        myClass=new MyClass(mainClass.getClassName(),mainClass.getConstantPoolType(),mainClass.getConstantPool(),mainClass.getFiledsName(),mainClass.getFields(),100);
        frame=new Frame(100,100);
        frame.setCurrentMethodIndex("main");
        frame.setLocal(0,myClass);
        myClass.pushFrame(frame);
        heap.addObject(myClass);
        Opcodes=mainClass.getMethods().get(frame.getCurrentMethodIndex());
        while (pc < Opcodes.length) {
            int instruction = Opcodes[pc]&(0xff);
            System.out.print(pc + " " + instructionNames[instruction]);
            if(instructionNames[instruction].contains("return")||instructionNames[instruction].contains("Return")){
                System.out.println("\nlocal variables");
                for(int i=0;i<frame.getLocalIndex();++i){
                    System.out.println(frame.getLocal(i));
                }
            }
            eval(fetch());
        }
    }

    public static void main(String[] args) {
        JavaVirtualMachine jvm = new JavaVirtualMachine();
        String[] directoryPaths = new String[3];
        directoryPaths[0]="C:\\Users\\HP\\IdeaProjects\\jvm_experiment_1\\target\\classes\\"; //实验1路径
        directoryPaths[1] = "C:\\Users\\HP\\IdeaProjects\\jvm_experiment_2\\target\\classes\\"; //实验2路径
        directoryPaths[2] = "C:\\Users\\HP\\IdeaProjects\\jvm_experiment_3\\target\\classes\\"; //实验3路径
        System.out.println("请输入想要进行的实验编号：");
        Scanner scanner = new Scanner(System.in);
        int experimentNumber = scanner.nextInt();
        jvm.run(directoryPaths[experimentNumber-1]);
    }
}

