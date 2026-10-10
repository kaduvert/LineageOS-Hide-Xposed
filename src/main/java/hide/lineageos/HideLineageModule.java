package lineageos.hide;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Xposed / LSPosed module — hides LineageOS ROM fingerprints from scoped apps.
 *
 * Scope to individual apps via the LSPosed Manager UI.
 * All hooks fire only inside the target app's process; nothing else is affected.
 *
 * Duck Detector report section → hook section in this file:
 *
 *   [Runtime]   serviceScan    §1  ServiceManager.getService / checkService / listServices
 *   [Runtime]   packageScan    §2  PackageManager direct lookup + list enumeration
 *   [Framework] nativeFiles    §3  File.exists / isFile / isDirectory / canRead
 *                                  File.list / listFiles  (directory traversal guard)
 *   [Framework] nativePolicy   §4  FileInputStream / RandomAccessFile open → ENOENT
 *   [Framework] nativeSymbols  §4  same — blocks ELF read of libstagefright.so
 *
 * What this module does NOT cover (not present in this report):
 *   - Native open(2) / stat(2) / readdir(2) via JNI/NDK — needs Zygisk+inline hooks
 *   - Runtime.exec() shell commands (find, ls, cat) — add a hook here if needed
 *   - __system_property_get() — propertyScan is Clean in this report
 */
public class HideLineageModule implements IXposedHookLoadPackage {

    // =========================================================================
    //  Data sets — edit these if your build has different service / package names
    // =========================================================================

    /** Services nulled out from getService() and stripped from listServices(). */
    private static final Set<String> HIDDEN_SERVICES = new HashSet<>(Arrays.asList(
            "profile",
            "lineageglobalactions",
            "lineagehardware",
            "lineagehealth",
            "lineagelivedisplay",
            "lineagetrust",
            "vendor.lineage.health.IChargingControl/default",
            "vendor.lineage.health.IFastCharge/default",
            "vendor.lineage.livedisplay.IPictureAdjustment/default"
    ));

    /**
     * Packages thrown as NameNotFoundException on direct lookup and removed
     * from list results.
     *
     * Only org.lineageos.jelly showed up in the report's packageScan (1 hit).
     * The overlay APKs are detected via the filesystem path checks in §3,
     * NOT through PackageManager — see the §2 comment block for why.
     */
    private static final Set<String> HIDDEN_PACKAGES = new HashSet<>(Arrays.asList(
            "org.lineageos.jelly"
            // Add further org.lineageos.* packages here if a target app
            // queries them directly and they show up in a packageScan hit.
    ));

    /**
     * Exact absolute paths that must appear absent (exists() == false)
     * and unopenable (FileInputStream throws ENOENT).
     */
    private static final Set<String> HIDDEN_EXACT_PATHS = new HashSet<>(Arrays.asList(
            // LineageOS platform framework JARs / compiled artifacts
            "/system/framework/org.lineageos.platform-res.apk",
            "/system/framework/oat/arm64/org.lineageos.platform.vdex",
            "/system/framework/oat/arm64/org.lineageos.platform.odex",

            // Custom ROM OTA hook directory (reported as "Script" type)
            "/system/addon.d",

            // §4 — ELF symbol scan: blocking FileInputStream prevents the
            //       .symtab/.dynsym walk for ANetworkSession::threadLoopEv.
            //       System.loadLibrary() uses the dynamic linker directly and
            //       does NOT go through FileInputStream, so media playback is
            //       unaffected.
            "/system/lib64/libstagefright.so",

            // §4 — SELinux policy content scan: these files are scanned for
            //       the strings "hal_lineage" (295 hits) and ".lineage" (16 hits).
            //       Normal apps have no legitimate reason to read CIL policy files.
            "/vendor/etc/selinux/vendor_sepolicy.cil",
            "/system_ext/etc/selinux/system_ext_sepolicy.cil",
            "/vendor/etc/selinux/vendor_file_contexts"
    ));

    /**
     * Substring-match hidden paths — any absolute path containing one of
     * these tokens is treated as hidden.
     *
     * Catches every auto-generated RRO overlay APK such as:
     *   /product/overlay/Settings__lineage_sargo__auto_generated_rro_product.apk
     *   /vendor/overlay/SystemUI__lineage_sargo__auto_generated_rro_vendor.apk
     *   /product/overlay/LineageBlackTheme
     * …without needing an explicit entry for each of the ~40 overlays.
     */
    private static final String[] HIDDEN_PATH_KEYWORDS = {
            "lineage",  // covers org.lineageos.*, *__lineage_sargo__*, LineageBlack*
            "addon.d",  // belt-and-suspenders for /system/addon.d
    };

    // =========================================================================
    //  Entry point
    // =========================================================================

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log("[HideLineage] active in " + lpparam.packageName);
        hookServiceManager(lpparam);
        hookPackageManager(lpparam);
        hookFileExistence();   // §3 — no ClassLoader needed; bootstrap classes
        hookFileOpen();        // §4 — same
    }

    // =========================================================================
    //  Predicates
    // =========================================================================

    private static boolean isHiddenService(String name) {
        return name != null
                && (HIDDEN_SERVICES.contains(name) || name.contains("lineage"));
    }

    private static boolean isHiddenPath(String path) {
        if (path == null) return false;
        if (HIDDEN_EXACT_PATHS.contains(path)) return true;
        for (String kw : HIDDEN_PATH_KEYWORDS) {
            if (path.contains(kw)) return true;
        }
        return false;
    }

    private static boolean isHiddenPackage(String pkg) {
        return pkg != null
                && (HIDDEN_PACKAGES.contains(pkg)
                    || pkg.startsWith("org.lineageos")
                    || pkg.startsWith("lineageos."));
    }

    // =========================================================================
    //  §1  ServiceManager
    //
    //  How detection works:
    //    android.os.ServiceManager is an ordinary Java static class callable
    //    from any app.  Each method dispatches a binder IPC to servicemanager,
    //    but the call originates in-process, so Xposed intercepts it before
    //    the transaction is sent.
    //
    //    getService(String)    blocks until the service is ready; returns IBinder
    //    checkService(String)  non-blocking variant; returns null if absent
    //    listServices()        returns String[] of every registered service name
    //    listServices(int)     API-30+ overload; int is a dumpPriority filter
    //
    //  Strategy:
    //    getService / checkService  → beforeHook: return null immediately
    //    listServices               → afterHook:  strip lineage entries from result
    // =========================================================================
    private void hookServiceManager(XC_LoadPackage.LoadPackageParam lpparam) {
        final String SM = "android.os.ServiceManager";
        final ClassLoader cl = lpparam.classLoader;

        tryHook("SM.getService", () ->
            XposedHelpers.findAndHookMethod(SM, cl, "getService", String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (isHiddenService((String) p.args[0])) p.setResult(null);
                    }
                })
        );

        tryHook("SM.checkService", () ->
            XposedHelpers.findAndHookMethod(SM, cl, "checkService", String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        if (isHiddenService((String) p.args[0])) p.setResult(null);
                    }
                })
        );

        tryHook("SM.listServices()", () ->
            XposedHelpers.findAndHookMethod(SM, cl, "listServices",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(filterServices((String[]) p.getResult()));
                    }
                })
        );

        // API 30+ overload
        tryHook("SM.listServices(int)", () ->
            XposedHelpers.findAndHookMethod(SM, cl, "listServices", int.class,
                new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(filterServices((String[]) p.getResult()));
                }
                })
        );
    }

    private static String[] filterServices(String[] src) {
        if (src == null) return null;
        List<String> out = new ArrayList<>(src.length);
        for (String s : src) {
            if (!isHiddenService(s)) out.add(s);
        }
        return out.toArray(new String[0]);
    }

    // =========================================================================
    //  §2  PackageManager
    //
    //  How detection works:
    //    The app calls standard PackageManager APIs from its own process.
    //    android.app.ApplicationPackageManager is the concrete in-process
    //    implementation returned by context.getPackageManager(); it proxies
    //    calls to the system server over binder, but we intercept at the Java
    //    layer before the IPC is dispatched.
    //
    //  Why don't the overlay APKs (40+ in the report) appear here?
    //    Auto-generated RRO overlay packages are installed as system packages
    //    but are marked MATCH_HIDDEN_UNTIL_INSTALLED.  getInstalledPackages(0)
    //    without privileged flags will not enumerate them.  Duck Detector finds
    //    them by checking their known filesystem paths directly (§3), NOT by
    //    asking PackageManager — that's why the report lists them under
    //    nativeFiles, not packageScan.
    //
    //    The one packageScan hit (org.lineageos.jelly) is a user-visible app
    //    that IS returned by normal PM enumeration, hence it needs PM hooks.
    //
    //  Strategy:
    //    Direct lookup  → beforeHook: throw NameNotFoundException
    //    List results   → afterHook:  remove hidden entries via Iterator
    //                     (Iterator.remove() is safe on the mutable ArrayList
    //                      that ApplicationPackageManager returns; if the system
    //                      ever returns an unmodifiable list the remove() is
    //                      silently swallowed)
    // =========================================================================
    private void hookPackageManager(XC_LoadPackage.LoadPackageParam lpparam) {
        final String APM = "android.app.ApplicationPackageManager";
        final ClassLoader cl = lpparam.classLoader;

        tryHook("PM.getPackageInfo(String,int)", () ->
            XposedHelpers.findAndHookMethod(APM, cl,
                    "getPackageInfo", String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if (isHiddenPackage((String) p.args[0]))
                            throw new PackageManager.NameNotFoundException((String) p.args[0]);
                    }
                })
        );

        tryHook("PM.getApplicationInfo(String,int)", () ->
            XposedHelpers.findAndHookMethod(APM, cl,
                    "getApplicationInfo", String.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if (isHiddenPackage((String) p.args[0]))
                            throw new PackageManager.NameNotFoundException((String) p.args[0]);
                    }
                })
        );

        tryHook("PM.getInstalledPackages(int)", () ->
            XposedHelpers.findAndHookMethod(APM, cl,
                    "getInstalledPackages", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        removeHiddenPkgInfos((List<?>) p.getResult());
                    }
                })
        );

        tryHook("PM.getInstalledApplications(int)", () ->
            XposedHelpers.findAndHookMethod(APM, cl,
                    "getInstalledApplications", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        removeHiddenAppInfos((List<?>) p.getResult());
                    }
                })
        );
    }

    @SuppressWarnings("unchecked")
    private static void removeHiddenPkgInfos(List<?> list) {
        if (list == null) return;
        Iterator<PackageInfo> it = ((List<PackageInfo>) list).iterator();
        while (it.hasNext()) {
            PackageInfo pi = it.next();
            if (pi != null && isHiddenPackage(pi.packageName)) {
                try { it.remove(); } catch (UnsupportedOperationException ignored) {}
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void removeHiddenAppInfos(List<?> list) {
        if (list == null) return;
        Iterator<ApplicationInfo> it = ((List<ApplicationInfo>) list).iterator();
        while (it.hasNext()) {
            ApplicationInfo ai = it.next();
            if (ai != null && isHiddenPackage(ai.packageName)) {
                try { it.remove(); } catch (UnsupportedOperationException ignored) {}
            }
        }
    }

    // =========================================================================
    //  §3  File existence / listing  (nativeFiles)
    //
    //  How detection works:
    //    Duck Detector maintains a hardcoded list of known LineageOS artifact
    //    paths and calls File.exists() on each one.  A single boolean "true"
    //    is all it needs to flag the entry — no file contents are read here.
    //    The word "native" in nativeFiles means "filesystem", not native code.
    //
    //  Strategy:
    //    exists / isFile / isDirectory / canRead
    //      → beforeHook: if path is hidden, setResult(false) before the real
    //        call is made.  The stat(2) syscall is never issued.
    //
    //    listFiles() / list() (directory traversal guard)
    //      → afterHook: strip any hidden entries from the returned array.
    //        This prevents discovery if the detector walks /product/overlay/
    //        or /vendor/overlay/ rather than checking known paths individually.
    //
    //  Note on ClassLoader:
    //    java.io.File and the stream classes below are loaded by the bootstrap
    //    ClassLoader, not the app ClassLoader.  We pass the Class object
    //    directly instead of a (name, ClassLoader) pair.
    // =========================================================================
    private void hookFileExistence() {
        final XC_MethodHook returnFalse = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                if (isHiddenPath(((File) p.thisObject).getAbsolutePath()))
                    p.setResult(false);
            }
        };

        for (String m : new String[]{"exists", "isFile", "isDirectory", "canRead"}) {
            tryHook("File." + m + "()", () ->
                XposedHelpers.findAndHookMethod(File.class, m, returnFalse)
            );
        }

        // listFiles() — returns File[]
        tryHook("File.listFiles()", () ->
            XposedHelpers.findAndHookMethod(File.class, "listFiles",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        File[] files = (File[]) p.getResult();
                        if (files == null) return;
                        List<File> out = new ArrayList<>(files.length);
                        for (File f : files) {
                            if (!isHiddenPath(f.getAbsolutePath())) out.add(f);
                        }
                        p.setResult(out.toArray(new File[0]));
                    }
                })
        );

        // list() — returns String[] of names, not full paths
        tryHook("File.list()", () ->
            XposedHelpers.findAndHookMethod(File.class, "list",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        String[] names = (String[]) p.getResult();
                        if (names == null) return;
                        // Reconstruct absolute paths so isHiddenPath can match keywords
                        String base = ((File) p.thisObject).getAbsolutePath() + "/";
                        List<String> out = new ArrayList<>(names.length);
                        for (String n : names) {
                            if (!isHiddenPath(base + n)) out.add(n);
                        }
                        p.setResult(out.toArray(new String[0]));
                    }
                })
        );
    }

    // =========================================================================
    //  §4  File open hooks  (nativePolicy + nativeSymbols)
    //
    //  --- nativePolicy ---
    //  How detection works:
    //    Duck Detector opens the SELinux binary CIL files:
    //      /vendor/etc/selinux/vendor_sepolicy.cil       (295 "hal_lineage" hits)
    //      /system_ext/etc/selinux/system_ext_sepolicy.cil (41 hits)
    //      /vendor/etc/selinux/vendor_file_contexts      ( 5 + 11 ".lineage" hits)
    //    It reads the raw bytes and scans for the strings "hal_lineage" and
    //    ".lineage".  The files are binary, so filtering their contents would
    //    require understanding the CIL encoding — much easier to block the open.
    //    Normal app code has no business reading SELinux policy CIL files.
    //
    //  --- nativeSymbols ---
    //  How detection works:
    //    Duck Detector reads the raw ELF binary at:
    //      /system/lib64/libstagefright.so
    //    It walks the .dynsym / .symtab sections looking for the mangled C++
    //    symbol  _ZN14ANetworkSession12threadLoopEvEv  (ANetworkSession::threadLoopEv),
    //    a pre-Treble Stagefright relic present in some LineageOS builds.
    //    RandomAccessFile is the likely vehicle because ELF parsers need seek().
    //
    //  Strategy:
    //    Hook the constructors of FileInputStream and RandomAccessFile.
    //    If the path matches anything in our hidden set, throw FileNotFoundException
    //    before the fd is opened — the detector either catches it and reports
    //    "unavailable" or crashes harmlessly.
    //
    //  IMPORTANT — why this doesn't break media playback:
    //    System.loadLibrary() / dlopen() ask the dynamic linker (in native code)
    //    to map the .so.  The linker opens the file using the native open(2)
    //    syscall directly, not through Java FileInputStream.  This hook is
    //    entirely invisible to the library loader.
    // =========================================================================
    private void hookFileOpen() {
        // Single hook instance reused across all four constructors — XC_MethodHook
        // is stateless; state lives in the MethodHookParam passed at call time.
        final XC_MethodHook throwIfHidden = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                Object arg = p.args[0];
                String path = (arg instanceof File)
                        ? ((File) arg).getAbsolutePath()
                        : (String) arg;
                if (isHiddenPath(path))
                    throw new FileNotFoundException(
                            "open failed: ENOENT (No such file or directory): " + path);
            }
        };

        tryHook("FileInputStream(String)", () ->
            XposedHelpers.findAndHookConstructor(
                    FileInputStream.class, String.class, throwIfHidden)
        );
        tryHook("FileInputStream(File)", () ->
            XposedHelpers.findAndHookConstructor(
                    FileInputStream.class, File.class, throwIfHidden)
        );
        // RandomAccessFile: arg[0] = path/File, arg[1] = mode string ("r", "rw", …)
        tryHook("RandomAccessFile(String,String)", () ->
            XposedHelpers.findAndHookConstructor(
                    RandomAccessFile.class, String.class, String.class, throwIfHidden)
        );
        tryHook("RandomAccessFile(File,String)", () ->
            XposedHelpers.findAndHookConstructor(
                    RandomAccessFile.class, File.class, String.class, throwIfHidden)
        );
    }

    // =========================================================================
    //  Utility
    // =========================================================================

    /**
     * Wraps hook registration so a missing method signature logs a warning
     * instead of crashing the whole module init (e.g. on API levels where
     * a particular overload doesn't exist yet).
     */
    private static void tryHook(String label, Runnable task) {
        try {
            task.run();
        } catch (Throwable t) {
            XposedBridge.log("[HideLineage] hook failed – " + label + ": " + t);
        }
    }
}
