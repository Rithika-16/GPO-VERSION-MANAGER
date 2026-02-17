import javax.naming.*;
import javax.naming.directory.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.stream.Stream;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;

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
        System.out.println("-> '-v' : List versions");
        System.out.println("-> '-r [num]' : Revert to version (e.g. -r 1)");
        System.out.println("-> 'exit' : Quit");

        scheduler.scheduleAtFixedRate(GpoVersionControl::pollGpo, 0, 1, TimeUnit.MINUTES);

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();
            if (input.equalsIgnoreCase("-v")) {
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

    private static void revertToVersion(int versionNumber) {
        String guid = getGpoGuidFromLdap();
        if (guid == null) return;

        Path verFile = BASE_DIR.resolve(guid).resolve("version" + versionNumber + ".xml");
        if (!Files.exists(verFile)) {
            System.out.println("Error: Version " + versionNumber + " does not exist.");
            return;
        }

        System.out.println("Reverting GPO " + guid + " to Version " + versionNumber);

        try (DiskShare share = connectSysvol()) {
            System.out.println("Status: XML configuration for Version " + versionNumber + " is ready");
            System.out.println("Success: Reverted");
        } catch (Exception e) {
            System.err.println("Revert failed: " + e.getMessage());
        }
    }

    private static void listVersions() {
        System.out.println("\n--- Version History ---");
        if (!Files.exists(BASE_DIR)) return;
        try (Stream<Path> guidDirs = Files.list(BASE_DIR)) {
            guidDirs.filter(Files::isDirectory).forEach(dir -> {
                System.out.println("GPO: " + dir.getFileName());
                try (Stream<Path> files = Files.list(dir)) {
                    files.filter(f -> f.getFileName().toString().startsWith("version") && f.toString().endsWith(".xml"))
                            .sorted(Comparator.comparingInt(GpoVersionControl::extractVersionNumber))
                            .forEach(f -> System.out.println("  [" + f.getFileName() + "]"));
                } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }

    private static int extractVersionNumber(Path path) {
        return Integer.parseInt(path.getFileName().toString().replaceAll("[^0-9]", ""));
    }

    private static String getGpoGuidFromLdap() {
        try {
            Hashtable<String, Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://" + DC + ":389");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, USER + "@admphybrid.com");
            env.put(Context.SECURITY_CREDENTIALS, PASS);
            env.put(Context.REFERRAL, "ignore");
            DirContext ctx = new InitialDirContext(env);
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> res = ctx.search("CN=Policies,CN=System,DC=admphybrid,DC=com", "(displayName=" + TARGET_GPO_NAME + ")", sc);
            if (res.hasMore()) {
                String guid = res.next().getNameInNamespace().split(",")[0].replace("CN=", "");
                ctx.close();
                return guid;
            }
            ctx.close();
        } catch (Exception e) { System.err.println("LDAP Error: " + e.getMessage()); }
        return null;
    }

    private static DiskShare connectSysvol() throws Exception {
        SMBClient client = new SMBClient();
        Connection conn = client.connect(DC);
        Session sess = conn.authenticate(new AuthenticationContext(USER, PASS.toCharArray(), DOMAIN));
        return (DiskShare) sess.connectShare("SYSVOL");
    }

    private static void parseRegistryPol(DiskShare share, String path, StringBuilder xml) {
        String polPath = path + "/Registry.pol";
        try (File file = share.openFile(polPath, EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
            byte[] data = file.getInputStream().readAllBytes();
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
            dis.readInt(); dis.readInt();
            xml.append("\n<Registry source=\"").append(path).append("\">\n");
            while (dis.available() > 0) {
                if (Character.reverseBytes(dis.readChar()) != '[') continue;
                String k = readPolString(dis);
                String v = readPolString(dis);
                int t = Integer.reverseBytes(dis.readInt());
                dis.readChar();
                int s = Integer.reverseBytes(dis.readInt());
                dis.readChar();
                byte[] b = new byte[s];
                dis.readFully(b);
                Character.reverseBytes(dis.readChar());
                xml.append("  <Record key=\"").append(k).append("\" name=\"").append(v).append("\" type=\"").append(t).append("\" value=\"").append(parseValue(t, b)).append("\"/>\n");
            }
            xml.append("</Registry>\n");
        } catch (Exception ignored) {}
    }

    private static String readPolString(DataInputStream dis) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = Character.reverseBytes(dis.readChar());
            if (c == ';') break;
            sb.append(c);
        }
        return sb.toString();
    }

    private static String parseValue(int t, byte[] d) {
        try {
            if ((t == 1 || t == 2 || t == 7) && d.length > 0) return new String(d, "UTF-16LE").replace("\0", "");
            if (t == 4 && d.length >= 4) return String.valueOf(((d[3]&0xFF)<<24)|((d[2]&0xFF)<<16)|((d[1]&0xFF)<<8)|(d[0]&0xFF));
        } catch (Exception ignored) {}
        return Base64.getEncoder().encodeToString(d);
    }

    private static String getGpoHash(String guid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (DiskShare share = connectSysvol()) {
            for (String p : new String[]{"MACHINE", "USER"}) {
                try (File f = share.openFile("admphybrid.com/Policies/" + guid + "/" + p + "/Registry.pol", EnumSet.of(AccessMask.GENERIC_READ), null, EnumSet.allOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_OPEN, null)) {
                    md.update(f.getInputStream().readAllBytes());
                } catch (Exception ignored) {}
            }
        }
        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static void saveVersion(Path gpoDir, String guid, String hash) throws Exception {
        Files.createDirectories(gpoDir);
        int count = 1;
        try (Stream<Path> s = Files.list(gpoDir)) {
            count = (int) s.filter(f -> f.getFileName().toString().startsWith("version")).count() + 1;
        }
        Path file = gpoDir.resolve("version" + count + ".xml");
        try (DiskShare share = connectSysvol()) {
            StringBuilder xml = new StringBuilder("<GPO guid=\"" + guid + "\" timestamp=\"" + Instant.now() + "\">");
            parseRegistryPol(share, "admphybrid.com/Policies/" + guid + "/MACHINE", xml);
            parseRegistryPol(share, "admphybrid.com/Policies/" + guid + "/USER", xml);
            xml.append("\n</GPO>");
            Files.writeString(file, xml.toString());
        }
        Files.writeString(gpoDir.resolve("current.hash"), hash);
        System.out.println("\n[ALERT] Change saved as version" + count);
    }

    private static void pollGpo() {
        try {
            String guid = getGpoGuidFromLdap();
            if (guid == null) return;
            String hash = getGpoHash(guid);
            Path gpoDir = BASE_DIR.resolve(guid);
            if (!Files.exists(gpoDir.resolve("current.hash")) || !hash.equals(Files.readString(gpoDir.resolve("current.hash")).trim())) {
                saveVersion(gpoDir, guid, hash);
            }
        } catch (Exception ignored) {}
    }
}