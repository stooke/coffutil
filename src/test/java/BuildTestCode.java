import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;

public class BuildTestCode {

    public static void main(String[] args) {
        try {
            PrintStream out = new PrintStream(new FileOutputStream("c:/tmp/build-1/test.cpp"));
            out.println("#include <iostream>\n\n");
            out.println("class ManyMembers {\n");
            out.println("public:");
            for (int i = 0; i < 10000; i++) {
                out.format("    virtual int mm_%05d(int a) {\n", i);
                out.format("        return a + %d;\n", i);
                out.format("    }\n");
            }
            out.println("    void go(int g) {\n" +
                    "        std::cout << \"test \" << mm_00000(g) << \"\\n\";\n" +
                    "    }");
            out.println("};\n\n");
            out.println("extern \"C\" int main(int argc, char* argv) {");
            out.println("    ManyMembers* mm = new ManyMembers;");
            out.println("    mm->go(0);\n");
            out.println("    delete mm;");
            out.println("}\n");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
