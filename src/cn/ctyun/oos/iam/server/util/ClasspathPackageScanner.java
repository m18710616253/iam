package cn.ctyun.oos.iam.server.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This scanner is used to find out all classes in a package.
 */
public class ClasspathPackageScanner {

    private Logger logger = LoggerFactory.getLogger(ClasspathPackageScanner.class);

    private ClassLoader classLoader;

    private List<String> includeFilter = new LinkedList<>();

    private List<String> excludeFilter = new LinkedList<>();

    /**
     * Construct an instance and specify the base package it should scan.
     */
    public ClasspathPackageScanner() {
        this.classLoader = getClass().getClassLoader();
        resetFilter(true);
    }

    /**
     * Construct an instance with base package and class loader.
     * @param classLoader Use this class load to locate the package.
     */
    public ClasspathPackageScanner(ClassLoader classLoader) {
        this.classLoader = classLoader == null ? getClass().getClassLoader() : classLoader;
        resetFilter(true);
    }

    /**
     * Add an include regex to the inclusion filter list
     * @param regex <br>
     */
    public void addIncludeFilter(String regex) {
        includeFilter.add(regex);
    }

    /**
     * Add an exclude regex to the exclusion filter list
     * @param regex <br>
     */
    public void addExcludeFilter(String regex) {
        excludeFilter.add(regex);
    }

    /**
     * Reset the configured filters.
     */
    public void resetFilter() {
        resetFilter(false);
    }
    /**
     * Reset the configured filters.
     * @param useDefaultFilter whether to re-register the default filter.
     */
    public void resetFilter(boolean useDefaultFilter) {
        includeFilter.clear();
        excludeFilter.clear();
        if (useDefaultFilter) {
            registerDefaultFilter();
        }
    }

    private void registerDefaultFilter() {
        includeFilter.add(".*");
    }

    public List<String> scan(String... basePackages)  {
        if (basePackages == null || basePackages.length == 0) {
            logger.info("basePackages is empty.");
            return null;
        }

        List<String> classNames = new ArrayList<>();
        for (String basePackage : basePackages) {
            logger.info("begin scan package[{}]", basePackage);
            try {
                classNames.addAll(doScan(basePackage));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return classNames;
    }
    
    /**
     * 获取指定包下的所有Class
     * @param basePackages
     * @param 指定注解
     * @return
     */
    public List<Class<?>> getClasses(String basePackages, Class<? extends Annotation> annotationClass)  {
        List<String> classNames = scan(basePackages);
        List<Class<?>> classes = new ArrayList<>();
        for (String name : classNames) {
            try {
                Class<?> clazz = Class.forName(name);
                if (clazz.isAnnotationPresent(annotationClass)) {
                    classes.add(clazz);
                }
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        return classes;
    }
    

    /**
     * Actually perform the scanning procedure.
     *
     * @param basePackage The base package to scan.
     * @return A list of fully qualified names.
     *
     * @throws IOException <br>
     */
    private List<String> doScan(String basePackage) throws IOException {
        List<String> classNames = new ArrayList<>();

        if (StringUtils.isEmpty(basePackage)) {
            logger.info("basePackages is empty.");
            return classNames;
        }

        // replace dots with splashes

        String splashPath = dotToSplash(basePackage);
        logger.info("splashPath is [{}]", splashPath);
        // get file path
        URL url = classLoader.getResource(splashPath);
        if (url == null) {
            String classPath = this.getClass().getName().replaceAll("\\.", "/") + ".class";
            URL resource = this.getClass().getClassLoader().getResource(classPath);
            url = new URL(resource.toString().replace(classPath, splashPath));
            logger.info("basePackage url is null, get resource form class, resource is [{}]", resource);
        }

        File file = toFile(url);
        if (file == null) {
            logger.warn("file is null, please check basePackage[{}] or URL[{}]", basePackage, url);
            return classNames;
        }

        // Get classes in that package.
        // If the web server unzips the jar file, then the classes will exist in the form of
        // normal file in the directory.
        // If the web server does not unzip the jar file, then classes will exist in jar file.
        List<String> names; // contains the name of the class file. e.g., Apple.class will be stored as "Apple"
        if (isJarFile(file.getName())) {
            // jar file
            names = readFromJarFile(file, splashPath);
        } else {
            // directory
            names = readFromDirectory(file, splashPath);
        }

        for (String name : names) {
            if (isClassFile(name)) {
                name = trimExtension(name);
                name = splashToDot(name);
                if (isMatch(name)) {
                    classNames.add(name);
                }
            }
        }

        return classNames;
    }

    private List<String> readFromJarFile(File file, String splashedPackageName) throws IOException {
        JarInputStream jarIn = new JarInputStream(new FileInputStream(file));
        List<String> nameList;
        try {
            JarEntry entry = jarIn.getNextJarEntry();
            nameList = new ArrayList<>();
            while (null != entry) {
                String name = entry.getName();
                if (name.startsWith(splashedPackageName) && isClassFile(name)) {
                    nameList.add(name);
                }
                entry = jarIn.getNextJarEntry();
            }
        } finally {
            jarIn.close();
        }
        return nameList;
    }

    private List<String> readFromDirectory(File file, String splashedPackageName) {
        List<String> nameList = new ArrayList<>();

        File[] files = file.listFiles();
        if (files != null) {
            for (File subFile : files) {
                if (subFile.isDirectory()) {
                    List<String> subDirectoryList = readFromDirectory(subFile,
                            splashedPackageName + "/" + subFile.getName());
                    if (subDirectoryList != null) {
                        nameList.addAll(subDirectoryList);
                    }
                } else if (isClassFile(subFile.getName())) {
                    nameList.add(splashedPackageName + "/" + subFile.getName());
                }
            }
        }

        return nameList;
    }

    private boolean isMatch(String input) {
        for (String regex : excludeFilter) {
            if (Pattern.matches(regex, input)) {
                return false;
            }
        }
        for (String regex : includeFilter) {
            if (Pattern.matches(regex, input)) {
                return true;
            }
        }
        return includeFilter.isEmpty(); // if inclusion filter is empty, that mean matched.
    }

    private boolean isClassFile(String name) {
        return name.endsWith(".class");
    }

    private boolean isJarFile(String name) {
        return name.endsWith(".jar");
    }
    

    /**
     * "file:/home/whf/cn/fh" -> "/home/whf/cn/fh" <br>
     * "jar:file:/home/whf/foo.jar!cn/fh" -> "/home/whf/foo.jar"
     */
    public static String getRootPath(URL url) {
        String urlPath = url.getPath();
        int pos = urlPath.indexOf('!');

        if (-1 == pos) {
            return urlPath;
        }

        return urlPath.substring(5, pos);
    }

    /**
     * Convert from a <code>URL</code> to a <code>File</code>.
     * <p>
     * this method will decode the URL.
     * Syntax such as <code>file:///my%20docs/file.txt</code> will be
     * correctly decoded to <code>/my docs/file.txt</code>.
     *
     * @param url  the file URL to convert, null returns null
     * @return the equivalent <code>File</code> object, or <code>null</code>
     * @throws IllegalArgumentException if the file is incorrectly encoded
     */
    public static File toFile(URL url) {
        if (url == null) {
            return null;
        } else {
            String filename = getRootPath(url).replace('/', File.separatorChar);
            int pos =0;
            while ((pos = filename.indexOf('%', pos)) >= 0) {
                if (pos + 2 < filename.length()) {
                    String hexStr = filename.substring(pos + 1, pos + 3);
                    char ch = (char) Integer.parseInt(hexStr, 16);
                    filename = filename.substring(0, pos) + ch + filename.substring(pos + 3);
                }
            }
            return new File(filename);
        }
    }

    /**
     * "cn.fh.lightning" -> "cn/fh/lightning"
     * @param string <br>
     * @return <br>
     */
    public static String dotToSplash(String string) {
        return string.replaceAll("\\.", "/");
    }

    /**
     * "cn/fh/lightning" -> "cn.fh.lightning"
     * @param string <br>
     * @return <br>
     */
    public static String splashToDot(String string) {
        return string.replaceAll("/", ".");
    }

    /**
     * "Apple.class" -> "Apple"
     */
    public static String trimExtension(String string) {
        int pos = string.lastIndexOf('.');
        if (-1 != pos) {
            return string.substring(0, pos);
        }
        return string;
    }
    
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        ClasspathPackageScanner packageScanner = new ClasspathPackageScanner(ClasspathPackageScanner.class.getClassLoader());
        List<String> classNames = packageScanner.scan("com.sun.activation.registries");

        for (String name : classNames) {
            System.out.println(Class.forName(name));
        }
    }
}