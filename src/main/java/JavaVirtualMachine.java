import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.Map;

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
    static int[] Opcodes = {0x10, 0x0A, 0x3C, 0x10, 0x14, 0x3D, 0x1B, 0x1C, 0x60, 0x3E, 0x1D, 0x10,
            0x0A, 0xA1, 0x00, 0x0A, 0x10, 0x0A, 0x36, 0x08, 0xA7, 0x00, 0x07, 0x10, 0x0A,
            0x36, 0x08, 0x1D, 0x9E, 0x00, 0x16, 0x10, 0x14, 0x36, 0x08, 0x1D, 0x04, 0x64,
            0x3E, 0x1D, 0x08, 0xA0, 0x00, 0x06, 0xA7, 0x00, 0x06, 0xA7, 0xFF, 0xEC, 0x12,
            0x02, 0x36, 0x05, 0x11, 0x03, 0xE8, 0x36, 0x06, 0xB1
    };
    static Frame frame=new Frame(100,100,100);
    static int print=0;


    static int fetch() {
        if(print>0)
            System.out.print(" "+Opcodes[pc]);
        print++;
        return Opcodes[pc++];
    }
    
    static int getOffset(){
        int bite_1 = fetch();
        int bite_2 = fetch();
        int combined = (bite_1 << 8) | bite_2;

        int offset;
        if ((combined & 0x8000) != 0) { // 如果最高位（符号位）为1，表示这是一个负数
            offset = combined - 0x10000; // 进行补码转换
        } else {
            offset = combined;
        }
        return offset;
    }
    
    public enum Instructions{
        Nop{
            @Override
            public void execute(@NotNull Frame frame) {
                // do nothing
            }
        },
        Aconst_null{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(null);
            }
        },
        Iconst_m1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(-1);
            }
        },
        Iconst_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(0);
            }
        },
        Iconst_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(1);
            }
        },
        Iconst_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(2);
            }
        },
        Iconst_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(3);
            }
        },
        Iconst_4{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(4);
            }
        },
        Iconst_5{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(5);
            }
        },
        Lconst_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(0L);
            }
        },
        Lconst_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(1L);
            }
        },
        Fconst_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(0.0f);
            }
        },
        Fconst_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(1.0f);
            }
        },
        Fconst_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(2.0f);
            }
        },
        Dconst_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(0.0);
            }
        },
        Dconst_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(1.0);
            }
        },
        Bipush{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(fetch());
            }
        },
        Sipush{
            @Override
            public void execute(@NotNull Frame frame) {
                int bite_1 = fetch();
                int bite_2 = fetch();
                int combined = (bite_1 << 8) | bite_2;
                frame.pushOperandStack(combined);
            }
        },
        Ldc{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getConstant(fetch()));
            }
        },
        Ldc_w{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getConstant(fetch()));
            }
        },
        Ldc2_w{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getConstant(fetch()));
            }
        },
        Iload{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(fetch()));
            }
        },
        Lload{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(fetch()));
            }
        },
        Fload{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(fetch()));
            }
        },
        Dload{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(fetch()));
            }
        },
        Aload{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(fetch()));
            }
        },
        Iload_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(0));
            }
        },
        Iload_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(1));
            }
        },
        Iload_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(2));
            }
        },
        Iload_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(3));
            }
        },
        Lload_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(0));
            }
        },
        Lload_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(1));
            }
        },
        Lload_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(2));
            }
        },
        Lload_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(3));
            }
        },
        Fload_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(0));
            }
        },
        Fload_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(1));
            }
        },
        Fload_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(2));
            }
        },
        Fload_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(3));
            }
        },
        Dload_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(0));
            }
        },
        Dload_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(1));
            }
        },
        Dload_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(2));
            }
        },
        Dload_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(3));
            }
        },
        Aload_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(0));
            }
        },
        Aload_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(1));
            }
        },
        Aload_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(2));
            }
        },
        Aload_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(frame.getLocal(3));
            }
        },
        Iaload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                int[] array = (int[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Laload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                long[] array = (long[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Faload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                float[] array = (float[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Daload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                double[] array = (double[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Aaload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                Object[] array = (Object[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Baload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                byte[] array = (byte[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Caload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                char[] array = (char[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Saload{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = (int) frame.popOperandStack();
                short[] array = (short[]) frame.popOperandStack();
                frame.pushOperandStack(array[index]);
            }
        },
        Istore{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Lstore{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Fstore{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Dstore{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Astore{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                frame.setLocal(index, frame.popOperandStack());
            }
        },
        Istore_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(0, frame.popOperandStack());
            }
        },
        Istore_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(1, frame.popOperandStack());
            }
        },
        Istore_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(2, frame.popOperandStack());
            }
        },
        Istore_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(3, frame.popOperandStack());
            }
        },
        Lstore_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(0, frame.popOperandStack());
            }
        },
        Lstore_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(1, frame.popOperandStack());
            }
        },
        Lstore_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(2, frame.popOperandStack());
            }
        },
        Lstore_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(3, frame.popOperandStack());
            }
        },
        Fstore_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(0, frame.popOperandStack());
            }
        },
        Fstore_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(1, frame.popOperandStack());
            }
        },
        Fstore_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(2, frame.popOperandStack());
            }
        },
        Fstore_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(3, frame.popOperandStack());
            }
        },
        Dstore_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(0, frame.popOperandStack());
            }
        },
        Dstore_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(1, frame.popOperandStack());
            }
        },
        Dstore_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(2, frame.popOperandStack());
            }
        },
        Dstore_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(3, frame.popOperandStack());
            }
        },
        Astore_0{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(0, frame.popOperandStack());
            }
        },
        Astore_1{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(1, frame.popOperandStack());
            }
        },
        Astore_2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(2, frame.popOperandStack());
            }
        },
        Astore_3{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.setLocal(3, frame.popOperandStack());
            }
        },
        Iastore{
            @Override
            public void execute(@NotNull Frame frame) {
                int value = (int) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                int[] array = (int[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Lastore{
            @Override
            public void execute(@NotNull Frame frame) {
                long value = (long) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                long[] array = (long[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Fastore{
            @Override
            public void execute(@NotNull Frame frame) {
                float value = (float) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                float[] array = (float[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Dastore{
            @Override
            public void execute(@NotNull Frame frame) {
                double value = (double) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                double[] array = (double[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Aastore{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value = frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                Object[] array = (Object[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Bastore{
            @Override
            public void execute(@NotNull Frame frame) {
                byte value = (byte) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                byte[] array = (byte[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Castore{
            @Override
            public void execute(@NotNull Frame frame) {
                char value = (char) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                char[] array = (char[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Sastore{
            @Override
            public void execute(@NotNull Frame frame) {
                short value = (short) frame.popOperandStack();
                int index = (int) frame.popOperandStack();
                short[] array = (short[]) frame.popOperandStack();
                array[index] = value;
            }
        },
        Pop{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.popOperandStack();
            }
        },
        Pop2{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.popOperandStack();
                frame.popOperandStack();
            }
        },
        Dup{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value = frame.popOperandStack();
                frame.pushOperandStack(value);
                frame.pushOperandStack(value);
            }
        },
        Dup_X1{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup_X2{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                Object value3 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value3);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup2{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
                frame.pushOperandStack(value1);
            }
        },
        Dup2_X1{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Dup2_X2{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Swap{
            @Override
            public void execute(@NotNull Frame frame) {
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                frame.pushOperandStack(value1);
                frame.pushOperandStack(value2);
            }
        },
        Iadd{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Ladd{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Fadd{
            @Override
            public void execute(@NotNull Frame frame) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Dadd{
            @Override
            public void execute(@NotNull Frame frame) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 + value2);
            }
        },
        Isub{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Lsub{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Fsub{
            @Override
            public void execute(@NotNull Frame frame) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Dsub{
            @Override
            public void execute(@NotNull Frame frame) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 - value2);
            }
        },
        Imul{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Lmul{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Fmul{
            @Override
            public void execute(@NotNull Frame frame) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Dmul{
            @Override
            public void execute(@NotNull Frame frame) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 * value2);
            }
        },
        Idiv{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Ldiv{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Fdiv{
            @Override
            public void execute(@NotNull Frame frame) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Ddiv{
            @Override
            public void execute(@NotNull Frame frame) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 / value2);
            }
        },
        Irem{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Lrem{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Frem{
            @Override
            public void execute(@NotNull Frame frame) {
                float value1 = (float) frame.popOperandStack();
                float value2 = (float) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Drem{
            @Override
            public void execute(@NotNull Frame frame) {
                double value1 = (double) frame.popOperandStack();
                double value2 = (double) frame.popOperandStack();
                frame.pushOperandStack(value1 % value2);
            }
        },
        Ineg{
            @Override
            public void execute(@NotNull Frame frame) {
                int value = (int) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Lneg{
            @Override
            public void execute(@NotNull Frame frame) {
                long value = (long) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Fneg{
            @Override
            public void execute(@NotNull Frame frame) {
                float value = (float) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Dneg{
            @Override
            public void execute(@NotNull Frame frame) {
                double value = (double) frame.popOperandStack();
                frame.pushOperandStack(-value);
            }
        },
        Ishl{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 << value2);
            }
        },
        Lshl{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 << value2);
            }
        },
        Ishr{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >> value2);
            }
        },
        Lshr{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >> value2);
            }
        },
        Iushr{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >>> value2);
            }
        },
        Lushr{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 >>> value2);
            }
        },
        Iand{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 & value2);
            }
        },
        Land{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 & value2);
            }
        },
        Ior{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 | value2);
            }
        },
        Lor{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 | value2);
            }
        },
        Ixor{
            @Override
            public void execute(@NotNull Frame frame) {
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                frame.pushOperandStack(value1 ^ value2);
            }
        },
        Lxor{
            @Override
            public void execute(@NotNull Frame frame) {
                long value1 = (long) frame.popOperandStack();
                long value2 = (long) frame.popOperandStack();
                frame.pushOperandStack(value1 ^ value2);
            }
        },
        Iinc{
            @Override
            public void execute(@NotNull Frame frame) {
                int index = fetch();
                int value = fetch();
                frame.setLocal(index, (int) frame.getLocal(index) + value);
            }
        },
        I2l{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((long) (int) frame.popOperandStack());
            }
        },
        I2f{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((float) (int) frame.popOperandStack());
            }
        },
        I2d{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((double) (int) frame.popOperandStack());
            }
        },
        L2i{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((int) (long) frame.popOperandStack());
            }
        },
        L2f{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((float) (long) frame.popOperandStack());
            }
        },
        L2d{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((double) (long) frame.popOperandStack());
            }
        },
        F2i{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((int) (float) frame.popOperandStack());
            }
        },
        F2l{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((long) (float) frame.popOperandStack());
            }
        },
        F2d{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((double) (float) frame.popOperandStack());
            }
        },
        D2i{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((int) (double) frame.popOperandStack());
            }
        },
        D2l{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((long) (double) frame.popOperandStack());
            }
        },
        D2f{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((float) (double) frame.popOperandStack());
            }
        },
        I2b{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((byte) (int) frame.popOperandStack());
            }
        },
        I2c{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((char) (int) frame.popOperandStack());
            }
        },
        I2s{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack((short) (int) frame.popOperandStack());
            }
        },
        Lcmp{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Fcmpl{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Fcmpg{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Dcmpl{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Dcmpg{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Ifeq{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value == 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifne{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value != 0) {
                    pc += offset - 3;
                }
            }
        },
        Iflt{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value < 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifge{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value >= 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifgt{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value > 0) {
                    pc += offset - 3;
                }
            }
        },
        Ifle{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value = (int) frame.popOperandStack();
                if (value <= 0) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpeq{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 == value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpne{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 != value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmplt{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 < value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpge{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 >= value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmpgt{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 > value2) {
                    pc += offset - 3;
                }
            }
        },
        If_icmple{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                int value1 = (int) frame.popOperandStack();
                int value2 = (int) frame.popOperandStack();
                if (value1 <= value2) {
                    pc += offset - 3;
                }
            }
        },
        If_acmpeq{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                if (value1 == value2) {
                    pc += offset - 3;
                }
            }
        },
        If_acmpne{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                Object value1 = frame.popOperandStack();
                Object value2 = frame.popOperandStack();
                if (value1 != value2) {
                    pc += offset - 3;
                }
            }
        },
        Goto{
            @Override
            public void execute(@NotNull Frame frame) {
                int offset=getOffset();
                pc += offset - 3;
            }
        },
        Jsr{
            @Override
            public void execute(@NotNull Frame frame) {
                frame.pushOperandStack(pc);
                pc += fetch();
            }
        },
        Ret{
            @Override
            public void execute(@NotNull Frame frame) {
                pc = (int)frame.getLocal(fetch());
            }
        },
        Tableswitch{
            @Override
            public void execute(@NotNull Frame frame) {
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
        Lookupswitch{
            @Override
            public void execute(@NotNull Frame frame) {
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
                if (pairs.containsKey(key)) {
                    pc += pairs.get(key);
                } else {
                    pc += defaultOffset;
                }
            }
        },
        Ireturn{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Lreturn{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Freturn{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Dreturn{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Areturn{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Return{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Getstatic{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Putstatic{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Getfield{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Putfield{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Invokevirtual{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Invokespecial{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Invokestatic{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Invokeinterface{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Invokedynamic{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        New{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Newarray{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Anewarray{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Arraylength{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Athrow{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Checkcast{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Instanceof{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Monitorenter{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Monitorexit{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Wide{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Multianewarray{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Ifnull{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Ifnonnull{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Goto_w{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        },
        Jsr_w{
            @Override
            public void execute(@NotNull Frame frame){
                //do nothing
            }
        };
    public abstract void execute(Frame frame);
    }


    void eval(int opcode) {
        Instructions instruction = Instructions.values()[opcode];
        instruction.execute(frame);
        System.out.println();
        print=0;
    }

    void run(){
        while (pc < Opcodes.length) {
            System.out.print(pc+" "+instructionNames[Opcodes[pc]]);
            eval(fetch());
        }
    }

    public static void main(String[] args) {
        JavaVirtualMachine jvm = new JavaVirtualMachine();
        jvm.run();
    }
}

