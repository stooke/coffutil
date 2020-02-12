package com.redhat.coffutil;

import java.io.File;
import java.io.IOException;

public interface ExeFileBuilder {
    ExeFile build(File file) throws IOException;
}
