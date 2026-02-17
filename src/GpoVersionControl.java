import javax.naming.*;
import javax.naming.directory.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.*;
import java.nio.charset.StandardCharsets;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.connection.Connection;
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
    private static final String DC = "10.63.47.47";
    private static final String DOMAIN = "admphybrid";
    private static final String USER = "rithikak";
    private static final String PASS = "Test@125$";
    private static final String TARGET_GPO_NAME = "New group policy object";

    public static void main(String[] args) throws Exception {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        System.out.println("GPO Version Manager");
        System.out.println("-> '-list' : List all domain GPOs");
        System.out.println("-> '-delete [name]' : Delete GPO from Domain");
        System.out.println("-> '-v' : List local versions");
        System.out.println("-> '-r [num]' : Revert to version");
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
            } else if (input.equalsIgnoreCase("exit")) {
                scheduler.shutdownNow();
                break;
            }
        }
    }

    private static void listDomainGpos() {
        try {
            DirContext ctx = getLdapContext();
            SearchControls ctls = new SearchControls();
            ctls.setReturningAttributes(new String[]{"displayName", "cn"});
            NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(objectClass=groupPolicyContainer)", ctls);
            System.out.println("\n--- Domain GPOs ---");
            while (res.hasMore()) {
                SearchResult sr = res.next();
                System.out.println(sr.getAttributes().get("displayName").get() + " " + sr.getAttributes().get("cn").get());
            }
            ctx.close();
        } catch (Exception e) {
            System.err.println("List failed: " + e.getMessage());
        }
    }

    private static void deleteGpo(String name) {
        try {
            String guid = getGpoGuidByName(name);
            if (guid == null) {
                System.out.println("GPO not found.");
                return;
            }
            DirContext ctx = getLdapContext();
            String dn = "CN=" + guid + ",CN=Policies,CN=System,DC=admphybrid,DC=com";

            // Delete LDAP container recursively (User/Machine sub-containers)
            deleteLdapRecursive(ctx, dn);
            ctx.close();

            // Delete SYSVOL folder recursively
            try (DiskShare share = connectSysvol()) {
                deleteSysvolRecursive(share, "admphybrid.com/Policies/" + guid);
            }
            System.out.println("SUCCESS: " + name + " deleted from AD and SYSVOL.");
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
            SearchResult child = children.next();
            String childDn = child.getNameInNamespace();
            if (!childDn.equalsIgnoreCase(dn)) {
                deleteLdapRecursive(ctx, childDn);
            }
        }
        ctx.destroySubcontext(dn);
    }

    private static void deleteSysvolRecursive(DiskShare share, String path) {
        for (com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation f : share.list(path)) {
            String name = f.getFileName();
            if (name.equals(".") || name.equals("..")) continue;
            String fullPath = path + "/" + name;
            if (f.getFileAttributes() == FileAttributes.FILE_ATTRIBUTE_DIRECTORY.getValue()) {
                deleteSysvolRecursive(share, fullPath);
            } else {
                share.rm(fullPath);
            }
        }
        share.rmdir(path, false);
    }
    private static String getGpoGuidByName(String name) throws Exception {
        DirContext ctx = getLdapContext();
        NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(displayName=" + name + ")", new SearchControls());
        String guid = null;
        if (res.hasMore()) guid = res.next().getAttributes().get("cn").get().toString();
        ctx.close();
        return guid;
    }

    private static void revertToVersion(int versionNumber) {
        String guid = getGpoGuidFromLdap();
        if (guid == null) return;

        Path xmlFile = BASE_DIR.resolve(guid).resolve("version" + versionNumber + ".xml");
        if (!Files.exists(xmlFile)) {
            System.out.println("Error: Version " + versionNumber + " does not exist.");
            return;
        }

        try {
            String xmlContent = Files.readString(xmlFile);
            try (DiskShare share = connectSysvol()) {

                byte[] mBytes = encodeXmlToPol(xmlContent, "MACHINE");
                if (mBytes != null) {
                    uploadToSysvol(share, mBytes, "admphybrid.com/Policies/" + guid + "/MACHINE/Registry.pol");
                }

                String infContent = encodeXmlToInf(xmlContent);
                if (infContent != null) {
                    byte[] textBytes = infContent.getBytes(StandardCharsets.UTF_16LE);
                    byte[] finalInf = new byte[textBytes.length + 2];
                    finalInf[0] = (byte) 0xFF; finalInf[1] = (byte) 0xFE;
                    System.arraycopy(textBytes, 0, finalInf, 2, textBytes.length);
                    uploadToSysvol(share, finalInf, "admphybrid.com/Policies/" + guid + "/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf");
                }

                String iniPath = "admphybrid.com/Policies/" + guid + "/GPT.ini";
                String iniContent = readRemoteText(share, iniPath, StandardCharsets.US_ASCII);
                String updatedIni = incrementGptVersion(iniContent);
                uploadToSysvol(share, updatedIni.getBytes(StandardCharsets.US_ASCII), iniPath);

                System.out.println("SUCCESS: Reverted to Version " + versionNumber + ". Version bumped to force client update.");
            }
        } catch (Exception e) {
            System.err.println("Revert failed: " + e.getMessage());
        }
    }

    private static String encodeXmlToInf(String xml) {
        Matcher sectionMatcher = Pattern.compile("<WindowsSettings>(.*?)</WindowsSettings>", Pattern.DOTALL).matcher(xml);
        if (!sectionMatcher.find()) return null;

        StringBuilder sb = new StringBuilder("[Unicode]\r\nUnicode=yes\r\n");
        String content = sectionMatcher.group(1);


        Pattern outerPattern = Pattern.compile("<([^/!>]+)>(.*?)</\\1>", Pattern.DOTALL);
        Matcher outerMatcher = outerPattern.matcher(content);

        while (outerMatcher.find()) {
            String sectionName = outerMatcher.group(1).trim();
            sb.append("[").append(sectionName).append("]\r\n");

            Matcher policyMatcher = Pattern.compile("<Policy name=\"(.*?)\" value=\"(.*?)\"/>").matcher(outerMatcher.group(2));
            while (policyMatcher.find()) {
                sb.append(policyMatcher.group(1))
                        .append(" = ")
                        .append(policyMatcher.group(2).replace("&quot;", "\""))
                        .append("\r\n");
            }
        }
        return sb.toString();
    }

    private static byte[] encodeXmlToPol(String xml, String section) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(Integer.reverseBytes(0x67655250));
        dos.writeInt(Integer.reverseBytes(1));

        String patternStr = "<Registry source=\".*?" + section + "\">(.*?)</Registry>";
        Matcher sectionMatcher = Pattern.compile(patternStr, Pattern.DOTALL).matcher(xml);
        if (!sectionMatcher.find()) return null;

        Matcher m = Pattern.compile("<Record key=\"(.*?)\" name=\"(.*?)\" type=\"(\\d+)\" value=\"(.*?)\"").matcher(sectionMatcher.group(1));
        int count = 0;
        while (m.find()) {
            dos.writeChar(Character.reverseBytes('['));
            writeUnicodeString(dos, m.group(1));
            dos.writeChar(Character.reverseBytes(';'));
            writeUnicodeString(dos, m.group(2));
            dos.writeChar(Character.reverseBytes(';'));
            int type = Integer.parseInt(m.group(3));
            dos.writeInt(Integer.reverseBytes(type));
            dos.writeChar(Character.reverseBytes(';'));
            byte[] data = decodeValue(type, m.group(4));
            dos.writeInt(Integer.reverseBytes(data.length));
            dos.writeChar(Character.reverseBytes(';'));
            dos.write(data);
            dos.writeChar(Character.reverseBytes(']'));
            count++;
        }
        return count > 0 ? baos.toByteArray() : null;
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

    private static String getGpoGuidFromLdap() {
        try {
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://" + DC + ":389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, USER + "@admphybrid.com");
            env.put(Context.SECURITY_CREDENTIALS, PASS);
            DirContext ctx = new InitialDirContext(env);
            NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(displayName=" + TARGET_GPO_NAME + ")", new SearchControls());
            if (res.hasMore()) return res.next().getNameInNamespace().split(",")[0].replace("CN=", "");
            ctx.close();
        } catch (Exception ignored) {}
        return null;
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
                byte[] b = new byte[s]; dis.readFully(b); Character.reverseBytes(dis.readChar());
                xml.append("  <Record key=\"").append(k).append("\" name=\"").append(v).append("\" type=\"").append(t).append("\" value=\"").append(parseValue(t, b)).append("\"/>\n");
            }
            xml.append("</Registry>\n");
        } catch (Exception ignored) {}
    }

    private static void parseWindowsSettings(DiskShare share, String guid, StringBuilder xml) {
        String path = "admphybrid.com/Policies/" + guid + "/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf";
        try (File f = share.openFile(path, EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null);
             BufferedReader br = new BufferedReader(new InputStreamReader(f.getInputStream(), StandardCharsets.UTF_16LE))) {
            xml.append("\n<WindowsSettings>\n");
            String section = null, line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith(";")) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    if (section != null) xml.append("  </").append(section).append(">\n");
                    section = line.substring(1, line.length() - 1);
                    xml.append("  <").append(section).append(">\n");
                } else if (section != null && line.contains("=")) {
                    String[] kv = line.split("=", 2);
                    xml.append("    <Policy name=\"").append(kv[0].trim()).append("\" value=\"").append(kv[1].trim().replace("\"", "&quot;")).append("\"/>\n");
                }
            }
            if (section != null) xml.append("  </").append(section).append(">\n");
            xml.append("</WindowsSettings>\n");
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

    private static String getGpoHash(String guid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (DiskShare share = connectSysvol()) {
            for (String p : new String[]{"/MACHINE/Registry.pol", "/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"}) {
                try (File f = share.openFile("admphybrid.com/Policies/" + guid + p, EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
                    md.update(f.getInputStream().readAllBytes());
                } catch (Exception ignored) {}
            }
        }
        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static void saveVersion(Path gpoDir, String guid, String hash) throws Exception {
        Files.createDirectories(gpoDir);
        long count = Files.list(gpoDir).filter(f -> f.getFileName().toString().startsWith("version")).count() + 1;
        try (DiskShare share = connectSysvol()) {
            StringBuilder xml = new StringBuilder("<GPO guid=\"" + guid + "\" timestamp=\"" + Instant.now() + "\">");
            parseRegistryPol(share, "admphybrid.com/Policies/" + guid + "/MACHINE", xml);
            parseWindowsSettings(share, guid, xml);
            xml.append("\n</GPO>");
            Files.writeString(gpoDir.resolve("version" + count + ".xml"), xml.toString());
        }
        Files.writeString(gpoDir.resolve("current.hash"), hash);
        System.out.println("\n Change saved as version" + count);
    }

    private static void pollGpo() {
        try {
            String guid = getGpoGuidFromLdap();
            if (guid == null) return;
            String hash = getGpoHash(guid);
            Path gpoDir = BASE_DIR.resolve(guid);
            if (!Files.exists(gpoDir.resolve("current.hash")) || !hash.equals(Files.readString(gpoDir.resolve("current.hash")).trim())) saveVersion(gpoDir, guid, hash);
        } catch (Exception ignored) {}
    }

    private static String readRemoteText(DiskShare share, String path, java.nio.charset.Charset charset) throws IOException {
        try (File f = share.openFile(path, EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
            return new BufferedReader(new InputStreamReader(f.getInputStream(), charset)).lines().collect(Collectors.joining("\r\n"));
        }
    }

    private static String incrementGptVersion(String iniContent) {
        Pattern p = Pattern.compile("(?i)(Version\\s*=\\s*)(\\d+)");
        Matcher m = p.matcher(iniContent);
        if (m.find()) return m.replaceFirst(m.group(1) + (Integer.parseInt(m.group(2)) + 1));
        return iniContent + "\r\nVersion=1";
    }
}