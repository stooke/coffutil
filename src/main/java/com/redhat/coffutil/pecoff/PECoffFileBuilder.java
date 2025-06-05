package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.ExeFileBuilder;
import com.redhat.coffutil.cv.CVSymbolSection;
import com.redhat.coffutil.cv.CVSymbolSectionBuilder;
import com.redhat.coffutil.cv.CVTypeSection;
import com.redhat.coffutil.cv.CVTypeSectionBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

public class PECoffFileBuilder extends CoffObjectFileBuilder implements ExeFileBuilder {

    public ExeFile build(File file) throws IOException {
        return buildPECoffFile(file);
    }

    public PECoffFile buildPECoffFile(File file) throws IOException {
        ByteBuffer in = Util.readFile(file);
        if (!in.hasRemaining()) {
            CoffUtilContext.getInstance().fatal("Input file %s is empty\n", file);
            return null;
        }
        return build(in);
    }

    private PECoffFile build(ByteBuffer in) {
        final PECoffFile coffFile;
        in.order(ByteOrder.LITTLE_ENDIAN);
        in.rewind();
        /* test if this is an executable or an object file */
        final short mzmaybe = in.getShort();
        if (mzmaybe == 0x5a4d) {
            CoffUtilContext.getInstance().debug("'MZ' detected; must be an executable\n");
            coffFile = parseExecutable(in);
        } else {
            /* should be a COFF object file */
            in.rewind();
            coffFile = parseCoff(in, false);
        }
        return coffFile;
    }

    private PECoffFile parseExecutable(ByteBuffer in) {
        final int e_lfanew = in.getInt(0x3c);
        //final long e_lfanew = in.getLong(0x3c);
        in.position(e_lfanew);
        return parseCoff(in, true);
    }

    private PECoffFile parseCoff(ByteBuffer in, boolean isPE) {

        final PEFileHeader hdr;
        final PESection[] sections;
        PERelocSection relocSection = null;
        PESymbolTable symbols = null;
        ArrayList<CVSymbolSection> cvSymbols = new ArrayList<>(10);
        ArrayList<CVTypeSection> cvTypes = new ArrayList<>(10);
        String directive = null;

        /* parse header */
        hdr = PEFileHeader.build(in);

        /* parse optional header */
        if (hdr.getOptionalHeaderSize() > 0) {
            int oldposition = in.position();
            //PEOptionalHeader32 ohdr = new PEOptionalHeader32(in);
            /* seek to start of section headers, in case optionalheader is padded */
            in.position(oldposition + hdr.getOptionalHeaderSize());
        }

        /* parse sections */
        sections = new PESection[hdr.getNumsections()];
        for (int n = 0; n < hdr.getNumsections(); n++) {
            PESection shdr = PESection.build(in, hdr);
            sections[n] = shdr;
        }

        /* parse symbols */
        if (hdr.getNumSymbols() > 0) {
            symbols = PESymbolTable.build(in, hdr);
        } /* if there's no symbol table at all, keep symbols null, instead of array[0] */

        /* look inside sections */
        CVSymbolSectionBuilder symbolSectionBuilder = new CVSymbolSectionBuilder(CoffUtilContext.getInstance());
        CVTypeSectionBuilder typeSectionBuilder = new CVTypeSectionBuilder(CoffUtilContext.getInstance());
        for (PESection shdr : sections) {
            final String sectionName = shdr.getName();
            /* load line numbers and relocations */
            switch (sectionName) {
                case ".debug$S":
                case ".debug_info":
                    cvSymbols.add(symbolSectionBuilder.build(in, shdr));
                    break;
                case ".debug$T":
                    cvTypes.add(typeSectionBuilder.build(in, shdr));
                    break;
                case ".drectve":
                    in.position(shdr.getRawDataPtr());
                    directive = Util.getString0(in, shdr.getRawDataSize());
                    break;
                case ".reloc":
                    relocSection = new PERelocSection(in, shdr, hdr);
                    break;
                default:
                    CoffUtilContext.getInstance().debug("unknown COFF section '" + shdr.getName() + "' \n");
            }
        }

        return new PECoffFile(hdr, sections, symbols, relocSection, cvSymbols, cvTypes, directive);
    }
}
