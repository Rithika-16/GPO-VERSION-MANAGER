import javax.naming.*;
import javax.naming.directory.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.*;
import java.nio.charset.StandardCharsets;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.msfscc.FileAttributes;

public class GpoVersionControl {

    private static final Path BASE_DIR = Paths.get("gpo_versions");
    private static final String DC = "xx.xx.xx.xx";
    private static final String DOMAIN = "domainname";
    private static final String USER = "username";
    private static final String PASS = "password";
    private static final String TARGET_GPO_NAME = "New group policy object";

    public static void main(String[] args) throws Exception {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        System.out.println("GPO Version Manager");
        System.out.println("-> '-list' : List all domain GPOs");
        System.out.println("-> '-delete [name]' : Delete GPO from Domain");
        System.out.println("-> '-v' : List local versions");
        System.out.println("-> '-r [num]' : Revert to version");
        System.out.println("-> '-link [GPO] [Target]' : Link Gpo to Target");
        System.out.println("-> 'exit' : Quit");

        scheduler.scheduleAtFixedRate(GpoVersionControl::pollGpo, 0, 1, TimeUnit.MINUTES);

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();
            if (input.equalsIgnoreCase("-list")) {
                listDomainGpos();
            } else if (input.startsWith("-delete ")) {
                deleteGpo(input.substring(8).trim());
            } else if (input.equalsIgnoreCase("-v")) {
                listVersions();
            } else if (input.startsWith("-r ")) {
                try {
                    int ver = Integer.parseInt(input.substring(3).trim());
                    revertToVersion(ver);
                } catch (Exception e) {
                    System.out.println("Invalid format. Use -r 1");
                }
            } else if (input.startsWith("-link ")) {
                try {
                    String rest = input.substring(6);
                    int splitIdx = rest.indexOf(" OU=");
                    if (splitIdx != -1) {
                        linkGpo(rest.substring(0, splitIdx).trim(), rest.substring(splitIdx).trim());
                    }else{
                        System.out.println("Enter a valid gpo name");
                    }
                } catch (Exception e) {
                    System.out.println("Invalid format.");
                }
            } else if (input.equalsIgnoreCase("exit")) {
                scheduler.shutdownNow();
                break;
            }
        }
    }

    private static class GpoInfo {
        String guid;
        int version;
        GpoInfo(String g, int v) { this.guid = g; this.version = v; }
    }

    private static void pollGpo() {
        try {
            GpoInfo info = getGpoInfoFromLdap(TARGET_GPO_NAME);
            if (info == null) return;

            Path gpoDir = BASE_DIR.resolve(info.guid);
            Path verFile = gpoDir.resolve("current.version");

            boolean isNew = true;
            if (Files.exists(verFile)) {
                int lastStoredVersion = Integer.parseInt(Files.readString(verFile).trim());
                if (lastStoredVersion == info.version) {
                    isNew = false;
                }
            }

            if (isNew) {
                saveVersion(gpoDir, info.guid, info.version);
            }
        } catch (Exception ignored) {}
    }

    private static GpoInfo getGpoInfoFromLdap(String displayName) {
        DirContext ctx = null;
        try {
            ctx = getLdapContext();
            SearchControls ctls = new SearchControls();
            ctls.setReturningAttributes(new String[]{"cn", "versionNumber"});
            NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(displayName=" + displayName + ")", ctls);
            if (res.hasMore()) {
                Attributes a = res.next().getAttributes();
                return new GpoInfo(a.get("cn").get().toString(), Integer.parseInt(a.get("versionNumber").get().toString()));
            }
        } catch (Exception ignored) {
        } finally {
            if (ctx != null) {
                try { ctx.close(); } catch (Exception ignored) {}
            }
        }
        return null;
    }

    private static void saveVersion(Path gpoDir, String guid, int adVersion) throws Exception {
        Files.createDirectories(gpoDir);
        long count = Files.list(gpoDir).filter(f -> f.getFileName().toString().startsWith("version")).count() + 1;
        try (DiskShare share = connectSysvol()) {
            StringBuilder xml = new StringBuilder("<GPO guid=\"" + guid + "\" adVersion=\"" + adVersion + "\" timestamp=\"" + Instant.now() + "\">");
            parseRegistryPol(share, "admphybrid.com/Policies/" + guid + "/MACHINE", xml);
            parseWindowsSettings(share, guid, xml);
            xml.append("\n</GPO>");
            Files.writeString(gpoDir.resolve("version" + count + ".xml"), xml.toString());
            Files.writeString(gpoDir.resolve("current.version"), String.valueOf(adVersion));
            System.out.println("\nChange saved as version" + count + " (AD Version: " + adVersion + ")");
        }
    }

    private static void revertToVersion(int localVerNum) {
        try {
            GpoInfo liveInfo = getGpoInfoFromLdap(TARGET_GPO_NAME);
            if (liveInfo == null) return;

            Path xmlFile = BASE_DIR.resolve(liveInfo.guid).resolve("version" + localVerNum + ".xml");
            if (!Files.exists(xmlFile)) {
                System.out.println("Local version not found.");
                return;
            }

            String xmlContent = Files.readString(xmlFile);
            try (DiskShare share = connectSysvol()) {
                byte[] mBytes = encodeXmlToPol(xmlContent, "MACHINE");
                if (mBytes != null) uploadToSysvol(share, mBytes, "admphybrid.com/Policies/" + liveInfo.guid + "/MACHINE/Registry.pol");

                String infContent = encodeXmlToInf(xmlContent);
                if (infContent != null) {
                    byte[] textBytes = infContent.getBytes(StandardCharsets.UTF_16LE);
                    byte[] finalInf = new byte[textBytes.length + 2];
                    finalInf[0] = (byte) 0xFF; finalInf[1] = (byte) 0xFE;
                    System.arraycopy(textBytes, 0, finalInf, 2, textBytes.length);
                    uploadToSysvol(share, finalInf, "admphybrid.com/Policies/" + liveInfo.guid + "/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf");
                }

                String iniPath = "admphybrid.com/Policies/" + liveInfo.guid + "/GPT.ini";
                String iniContent = readRemoteText(share, iniPath, StandardCharsets.US_ASCII);
                uploadToSysvol(share, incrementGptVersion(iniContent).getBytes(StandardCharsets.US_ASCII), iniPath);

                System.out.println("SUCCESS: Reverted to version " + localVerNum);
            }
        } catch (Exception e) {
            System.err.println("Revert failed: " + e.getMessage());
        }
    }

    private static String incrementGptVersion(String iniContent) {
        Pattern p = Pattern.compile("(?i)(Version\\s*=\\s*)(\\d+)");
        Matcher m = p.matcher(iniContent);
        if (m.find()) return m.replaceFirst(m.group(1) + (Integer.parseInt(m.group(2)) + 1));
        return iniContent;
    }

    private static void linkGpo(String Gpo_name, String Target) throws Exception {
        GpoInfo info = getGpoInfoFromLdap(Gpo_name);
        if (info == null) {
            System.out.println("GPO not found.");
            return;
        }
        String gpoDn = "CN=" + info.guid + ",CN=Policies,CN=System,DC=admphybrid,DC=com";
        String newLink = "[LDAP://" + gpoDn + ";0]";

        DirContext ctx = getLdapContext();
        try {
            Attributes attrs = ctx.getAttributes(Target, new String[]{"gPLink"});
            Attribute attr = attrs.get("gPLink");
            String finalGPLinkValue = (attr != null && attr.get() != null) ? newLink + (String) attr.get() : newLink;
            ModificationItem[] mods = { new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("gPLink", finalGPLinkValue)) };
            ctx.modifyAttributes(Target, mods);
            System.out.println("SUCCESS: Linked '" + Gpo_name + "' to " + Target);
        } finally {
            ctx.close();
        }
    }

    private static void listDomainGpos() {
        DirContext ctx = null;
        try {
            ctx = getLdapContext();
            NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(objectClass=groupPolicyContainer)", new SearchControls());
            while (res.hasMore()) {
                Attributes a = res.next().getAttributes();
                System.out.println(a.get("displayName").get() + " " + a.get("cn").get());
            }
        } catch (Exception e) {
            System.err.println("List failed: " + e.getMessage());
        } finally {
            if (ctx != null) {
                try { ctx.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void deleteGpo(String name) {
        try {
            GpoInfo info = getGpoInfoFromLdap(name);
            if (info == null) return;
            DirContext ctx = getLdapContext();
            deleteLdapRecursive(ctx, "CN=" + info.guid + ",CN=Policies,CN=System,DC=admphybrid,DC=com");
            ctx.close();
            try (DiskShare share = connectSysvol()) {
                deleteSysvolRecursive(share, "admphybrid.com/Policies/" + info.guid);
            }
            System.out.println("SUCCESS: " + name + " deleted.");
        } catch (Exception e) {
            System.err.println("Delete failed: " + e.getMessage());
        }
    }

    private static DirContext getLdapContext() throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + DC + ":389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, USER + "@admphybrid.com");
        env.put(Context.SECURITY_CREDENTIALS, PASS);
        return new InitialDirContext(env);
    }

    private static void deleteLdapRecursive(DirContext ctx, String dn) throws NamingException {
        NamingEnumeration<SearchResult> children = ctx.search(dn, "(objectClass=*)", new SearchControls());
        while (children.hasMore()) {
            String childDn = children.next().getNameInNamespace();
            if (!childDn.equalsIgnoreCase(dn)) deleteLdapRecursive(ctx, childDn);
        }
        ctx.destroySubcontext(dn);
    }

    private static void deleteSysvolRecursive(DiskShare share, String path) {
        for (com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation f : share.list(path)) {
            String name = f.getFileName();
            if (name.equals(".") || name.equals("..")) continue;
            String fullPath = path + "/" + name;
            if (f.getFileAttributes() == FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) deleteSysvolRecursive(share, fullPath);
            else share.rm(fullPath);
        }
        share.rmdir(path, false);
    }

    private static byte[] encodeXmlToPol(String xml, String section) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(Integer.reverseBytes(0x67655250));
        dos.writeInt(Integer.reverseBytes(1));
        Matcher m = Pattern.compile("<Record key=\"(.*?)\" name=\"(.*?)\" type=\"(\\d+)\" value=\"(.*?)\"").matcher(xml);
        int count = 0;
        while (m.find()) {
            dos.writeChar(Character.reverseBytes('['));
            writeUnicodeString(dos, m.group(1)); dos.writeChar(Character.reverseBytes(';'));
            writeUnicodeString(dos, m.group(2)); dos.writeChar(Character.reverseBytes(';'));
            int t = Integer.parseInt(m.group(3));
            dos.writeInt(Integer.reverseBytes(t)); dos.writeChar(Character.reverseBytes(';'));
            byte[] d = decodeValue(t, m.group(4));
            dos.writeInt(Integer.reverseBytes(d.length)); dos.writeChar(Character.reverseBytes(';'));
            dos.write(d); dos.writeChar(Character.reverseBytes(']'));
            count++;
        }
        return count > 0 ? baos.toByteArray() : null;
    }

    private static String encodeXmlToInf(String xml) {
        Matcher m = Pattern.compile("<WindowsSettings>(.*?)</WindowsSettings>", Pattern.DOTALL).matcher(xml);
        if (!m.find()) return null;
        return "[Unicode]\r\nUnicode=yes\r\n" + m.group(1).replaceAll("<([^/!>]+)>", "[$1]\r\n").replaceAll("</[^>]+>", "").replaceAll("<Policy name=\"(.*?)\" value=\"(.*?)\"/>", "$1 = $2\r\n");
    }

    private static byte[] decodeValue(int type, String val) throws IOException {
        if (type == 4) return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(Integer.parseInt(val)).array();
        if (type == 1 || type == 2 || type == 7) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            for (char c : (val + "\0").toCharArray()) { b.write(c & 0xFF); b.write((c >> 8) & 0xFF); }
            return b.toByteArray();
        }
        return Base64.getDecoder().decode(val);
    }

    private static void writeUnicodeString(DataOutputStream dos, String str) throws IOException {
        for (char c : str.toCharArray()) dos.writeChar(Character.reverseBytes(c));
        dos.writeChar(0);
    }

    private static void uploadToSysvol(DiskShare share, byte[] data, String path) throws IOException {
        try (File f = share.openFile(path, EnumSet.of(AccessMask.GENERIC_WRITE), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OVERWRITE_IF, null)) {
            f.write(data, 0);
        }
    }

    private static void listVersions() {
        if (!Files.exists(BASE_DIR)) return;
        try (DirectoryStream<Path> guidDirs = Files.newDirectoryStream(BASE_DIR)) {
            for (Path dir : guidDirs) {
                if (!Files.isDirectory(dir)) continue;
                System.out.println("GPO: " + dir.getFileName());
                Files.list(dir).filter(f -> f.toString().endsWith(".xml")).sorted().forEach(f -> System.out.println("  [" + f.getFileName() + "]"));
            }
        } catch (IOException ignored) {}
    }

    private static DiskShare connectSysvol() throws Exception {
        Session sess = new SMBClient().connect(DC).authenticate(new AuthenticationContext(USER, PASS.toCharArray(), DOMAIN));
        return (DiskShare) sess.connectShare("SYSVOL");
    }

    private static void parseRegistryPol(DiskShare share, String path, StringBuilder xml) {
        try (File file = share.openFile(path + "/Registry.pol", EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(file.getInputStream().readAllBytes()));
            dis.readInt(); dis.readInt();
            xml.append("\n<Registry source=\"").append(path).append("\">\n");
            while (dis.available() > 0) {
                if (Character.reverseBytes(dis.readChar()) != '[') continue;
                String k = readPolString(dis), v = readPolString(dis);
                int t = Integer.reverseBytes(dis.readInt()); dis.readChar();
                int s = Integer.reverseBytes(dis.readInt()); dis.readChar();
                byte[] b = new byte[s]; dis.readFully(b); dis.readChar();
                xml.append("  <Record key=\"").append(k).append("\" name=\"").append(v).append("\" type=\"").append(t).append("\" value=\"").append(parseValue(t, b)).append("\"/>\n");
            }
            xml.append("</Registry>\n");
        } catch (Exception ignored) {}
    }

    private static void parseWindowsSettings(DiskShare share, String guid, StringBuilder xml) {
        String path = "admphybrid.com/Policies/" + guid + "/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf";
        try {
            String content = readRemoteText(share, path, StandardCharsets.UTF_16LE);
            xml.append("\n<WindowsSettings>\n").append(content.replaceAll("\\[(.*?)\\]", "<$1>").replaceAll("(.*?) = (.*?)", "<Policy name=\"$1\" value=\"$2\"/>")).append("\n</WindowsSettings>\n");
        } catch (Exception ignored) {}
    }

    private static String readPolString(DataInputStream dis) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) { char c = Character.reverseBytes(dis.readChar()); if (c == ';') break; sb.append(c); }
        return sb.toString();
    }

    private static String parseValue(int t, byte[] d) {
        try {
            if ((t == 1 || t == 2 || t == 7) && d.length > 0) return new String(d, "UTF-16LE").replace("\0", "");
            if (t == 4) return String.valueOf(((d[3]&0xFF)<<24)|((d[2]&0xFF)<<16)|((d[1]&0xFF)<<8)|(d[0]&0xFF));
        } catch (Exception ignored) {}
        return Base64.getEncoder().encodeToString(d);
    }

    private static String readRemoteText(DiskShare share, String path, java.nio.charset.Charset charset) throws IOException {
        try (File f = share.openFile(path, EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
            return new BufferedReader(new InputStreamReader(f.getInputStream(), charset)).lines().collect(Collectors.joining("\r\n"));
        }
    }
}
