/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.common.extension;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.logger.Logger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.utils.StringUtils;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Code generator for Adaptive class
 */
public class AdaptiveClassCodeGenerator {
    
    private static final Logger logger = LoggerFactory.getLogger(AdaptiveClassCodeGenerator.class);

    private static final String CLASSNAME_INVOCATION = "org.apache.dubbo.rpc.Invocation";
    
    private static final String CODE_PACKAGE = "package %s;\n";
    
    private static final String CODE_IMPORTS = "import %s;\n";
    
    private static final String CODE_CLASS_DECLARATION = "public class %s$Adaptive implements %s {\n";
    
    private static final String CODE_METHOD_DECLARATION = "public %s %s(%s) %s {\n%s}\n";
    
    private static final String CODE_METHOD_ARGUMENT = "%s arg%d";
    
    private static final String CODE_METHOD_THROWS = "throws %s";
    
    private static final String CODE_UNSUPPORTED = "throw new UnsupportedOperationException(\"The method %s of interface %s is not adaptive method!\");\n";
    
    private static final String CODE_URL_NULL_CHECK = "if (arg%d == null) throw new IllegalArgumentException(\"url == null\");\n%s url = arg%d;\n";
    
    private static final String CODE_EXT_NAME_ASSIGNMENT = "String extName = %s;\n";
    
    private static final String CODE_EXT_NAME_NULL_CHECK = "if(extName == null) "
                    + "throw new IllegalStateException(\"Failed to get extension (%s) name from url (\" + url.toString() + \") use keys(%s)\");\n";
    
    private static final String CODE_INVOCATION_ARGUMENT_NULL_CHECK = "if (arg%d == null) throw new IllegalArgumentException(\"invocation == null\"); "
                    + "String methodName = arg%d.getMethodName();\n";
    
    
    private static final String CODE_EXTENSION_ASSIGNMENT = "%s extension = (%<s)%s.getExtensionLoader(%s.class).getExtension(extName);\n";
    
    private final Class<?> type;
    
    private String defaultExtName;
    
    public AdaptiveClassCodeGenerator(Class<?> type, String defaultExtName) {
        this.type = type;
        this.defaultExtName = defaultExtName;
    }
    
    /**
     * test if given type has at least one method annotated with <code>SPI</code>
     */
    private boolean hasAdaptiveMethod() {
        return Arrays.stream(type.getMethods()).anyMatch(m -> m.isAnnotationPresent(Adaptive.class));
    }
    
    /**
     * generate and return class code
     * 自适应拓展类代码生成
     *
     */
    public String generate() {
        // no need to generate adaptive class since there's no adaptive method found.
        //1.Adaptive 注解检测
        if (!hasAdaptiveMethod()) {
            // 若所有的方法上均无 Adaptive 注解，则抛出异常
            throw new IllegalStateException("No adaptive method exist on extension " + type.getName() + ", refuse to create the adaptive class!");
        }
        //2.生成类
        //通过 Adaptive 注解检测后，即可开始生成代码。
        // 代码生成的顺序与 Java 文件内容顺序一致，首先会生成 package 语句，然后生成 import 语句，紧接着生成类名等代码
        StringBuilder code = new StringBuilder();
        // 生成 package 代码：package + type 所在包
        code.append(generatePackageInfo());
        // 生成 import 代码：import + ExtensionLoader 全限定名
        code.append(generateImports());
        // 生成类代码：public class + type简单名称 + $Adaptive + implements + type全限定名 + {
        code.append(generateClassDeclaration());
        // 生成方法
        //无 Adaptive 注解方法代码生成逻辑
        //对于接口方法，我们可以按照需求标注 Adaptive 注解。
        // 以 Protocol 接口为例，该接口的 destroy 和 getDefaultPort 未标注 Adaptive 注解，
        // 其他方法均标注了 Adaptive 注解。
        // Dubbo 不会为没有标注 Adaptive 注解的方法生成代理逻辑，对于该种类型的方法，仅会生成一句抛出异常的代码
        Method[] methods = type.getMethods();
        for (Method method : methods) {
            code.append(generateMethod(method));
        }
        code.append("}");
        
        if (logger.isDebugEnabled()) {
            logger.debug(code.toString());
        }
        return code.toString();
    }

    /**
     * generate package info
     */
    private String generatePackageInfo() {
        return String.format(CODE_PACKAGE, type.getPackage().getName());
    }

    /**
     * generate imports
     */
    private String generateImports() {
        return String.format(CODE_IMPORTS, ExtensionLoader.class.getName());
    }

    /**
     * generate class declaration
     */
    private String generateClassDeclaration() {
        return String.format(CODE_CLASS_DECLARATION, type.getSimpleName(), type.getCanonicalName());
    }
    
    /**
     * generate method not annotated with Adaptive with throwing unsupported exception 
     */
    private String generateUnsupported(Method method) {
        return String.format(CODE_UNSUPPORTED, method, type.getName());
    }
    
    /**
     * get index of parameter with type URL
     */
    private int getUrlTypeIndex(Method method) {            
        int urlTypeIndex = -1;
        Class<?>[] pts = method.getParameterTypes();
        for (int i = 0; i < pts.length; ++i) {
            if (pts[i].equals(URL.class)) {
                urlTypeIndex = i;
                break;
            }
        }
        return urlTypeIndex;
    }
    
    /**
     * generate method declaration
     */
    private String generateMethod(Method method) {
        String methodReturnType = method.getReturnType().getCanonicalName();
        String methodName = method.getName();
        String methodContent = generateMethodContent(method);
        String methodArgs = generateMethodArguments(method);
        String methodThrows = generateMethodThrows(method);
        return String.format(CODE_METHOD_DECLARATION, methodReturnType, methodName, methodArgs, methodThrows, methodContent);
    }

    /**
     * generate method arguments
     */
    private String generateMethodArguments(Method method) {
        Class<?>[] pts = method.getParameterTypes();
        return IntStream.range(0, pts.length)
                        .mapToObj(i -> String.format(CODE_METHOD_ARGUMENT, pts[i].getCanonicalName(), i))
                        .collect(Collectors.joining(", "));
    }
    
    /**
     * generate method throws 
     */
    private String generateMethodThrows(Method method) {
        Class<?>[] ets = method.getExceptionTypes();
        if (ets.length > 0) {
            String list = Arrays.stream(ets).map(Class::getCanonicalName).collect(Collectors.joining(", "));
            return String.format(CODE_METHOD_THROWS, list);
        } else {
            return "";
        }
    }
    
    /**
     * generate method URL argument null check 
     */
    private String generateUrlNullCheck(int index) {
        // 为 URL 类型参数生成赋值代码，形如 URL url = arg1
        return String.format(CODE_URL_NULL_CHECK, index, URL.class.getName(), index);
    }
    
    /**
     * generate method content
     * 生成方法内容
     */
    private String generateMethodContent(Method method) {
        Adaptive adaptiveAnnotation = method.getAnnotation(Adaptive.class);
        StringBuilder code = new StringBuilder(512);

        if (adaptiveAnnotation == null) {
            // ${无 Adaptive 注解方法代码生成逻辑}
            return generateUnsupported(method);
        } else {
            // 遍历参数列表，确定 URL 参数位置
            int urlTypeIndex = getUrlTypeIndex(method);
            
            // found parameter in URL type
            // urlTypeIndex != -1，表示参数列表中存在 URL 参数
            if (urlTypeIndex != -1) {
                // Null Point check
                // 为 URL 类型参数生成判空代码，格式如下：
                // if (arg + urlTypeIndex == null)
                //     throw new IllegalArgumentException("url == null");
                code.append(generateUrlNullCheck(urlTypeIndex));
            // 参数列表中不存在 URL 类型参数
            } else {
                // did not find parameter in URL type
                code.append(generateUrlAssignmentIndirectly(method));
            }

            //获取Adaptive的注解值
            String[] value = getMethodAdaptiveValue(adaptiveAnnotation);

            boolean hasInvocation = hasInvocationArgument(method);
            
            code.append(generateInvocationArgumentNullCheck(method));
            //生成拓展名获取逻辑
            code.append(generateExtNameAssignment(value, hasInvocation));
            // check extName == null?
            code.append(generateExtNameNullCheck(value));
            //生成拓展加载与目标方法调用逻辑
            // 生成拓展获取代码，格式如下：
            // type全限定名 extension = (type全限定名)ExtensionLoader全限定名
            //     .getExtensionLoader(type全限定名.class).getExtension(extName);
            // Tips: 格式化字符串中的 %<s 表示使用前一个转换符所描述的参数，即 type 全限定名
            code.append(generateExtensionAssignment());

            // return statement
            // 生成目标方法调用逻辑，格式为：
            //     extension.方法名(arg0, arg2, ..., argN);
            code.append(generateReturnAndInovation(method));

           // 以 Protocol 接口举例说明，上面代码生成的内容如下：

         //   com.alibaba.dubbo.rpc.Protocol extension = (com.alibaba.dubbo.rpc.Protocol) ExtensionLoader
        //            .getExtensionLoader(com.alibaba.dubbo.rpc.Protocol.class).getExtension(extName);
         //   return extension.refer(arg0, arg1);
        }
        
        return code.toString();
    }

    /**
     * generate code for variable extName null check
     */
    private String generateExtNameNullCheck(String[] value) {
        return String.format(CODE_EXT_NAME_NULL_CHECK, type.getName(), Arrays.toString(value));
    }

    /**
     * generate extName assigment code
     */
    private String generateExtNameAssignment(String[] value, boolean hasInvocation) {
        // TODO: refactor it
        String getNameCode = null;
        for (int i = value.length - 1; i >= 0; --i) {
            if (i == value.length - 1) {
                //如果默认拓展名不为空 defaultExtName为dubbo, Protocol接口默认SPI为dubbo,这里就是接口 @SPI注解的值
                if (null != defaultExtName) {
                    // protocol 是 url 的一部分，可通过 getProtocol 方法获取，其他的则是从
                    // URL 参数中获取。因为获取方式不同，所以这里要判断 value[i] 是否为 protocol
                    if (!"protocol".equals(value[i])) {
                        // hasInvocation 用于标识方法参数列表中是否有 Invocation 类型参数
                        if (hasInvocation) {
                            // 生成的代码功能等价于下面的代码：
                            //   url.getMethodParameter(methodName, value[i], defaultExtName)
                            // 以 LoadBalance 接口的 select 方法为例，最终生成的代码如下：
                            //   url.getMethodParameter(methodName, "loadbalance", "random")
                            getNameCode = String.format("url.getMethodParameter(methodName, \"%s\", \"%s\")", value[i], defaultExtName);
                        } else {
                            // 生成的代码功能等价于下面的代码：
                            //   url.getParameter(value[i], defaultExtName)
                            getNameCode = String.format("url.getParameter(\"%s\", \"%s\")", value[i], defaultExtName);
                        }
                    } else {
                        // 生成的代码功能等价于下面的代码：
                        //   ( url.getProtocol() == null ? defaultExtName : url.getProtocol() )
                        getNameCode = String.format("( url.getProtocol() == null ? \"%s\" : url.getProtocol() )", defaultExtName);
                    }
                // 如果默认拓展名为空
                } else {
                    if (!"protocol".equals(value[i])) {
                        if (hasInvocation) {
                            getNameCode = String.format("url.getMethodParameter(methodName, \"%s\", \"%s\")", value[i], defaultExtName);
                        } else {
                            // 生成的代码功能等价于下面的代码：
                            //   url.getParameter(value[i], getNameCode)
                            // 以 Transporter 接口的 connect 方法为例，最终生成的代码如下：
                            //   url.getParameter("client", url.getParameter("transporter", "netty"))
                            getNameCode = String.format("url.getParameter(\"%s\")", value[i]);
                        }
                    } else {
                        getNameCode = "url.getProtocol()";
                    }
                }
            } else {
                if (!"protocol".equals(value[i])) {
                    if (hasInvocation) {
                        getNameCode = String.format("url.getMethodParameter(methodName, \"%s\", \"%s\")", value[i], defaultExtName);
                    } else {
                        getNameCode = String.format("url.getParameter(\"%s\", %s)", value[i], getNameCode);
                    }
                } else {
                    getNameCode = String.format("url.getProtocol() == null ? (%s) : url.getProtocol()", getNameCode);
                }
            }
        }
        
        return String.format(CODE_EXT_NAME_ASSIGNMENT, getNameCode);
    }

    /**
     * @return
     */
    private String generateExtensionAssignment() {
        return String.format(CODE_EXTENSION_ASSIGNMENT, type.getName(), ExtensionLoader.class.getSimpleName(), type.getName());
    }

    /**
     * generate method invocation statement and return it if necessary
     */
    private String generateReturnAndInovation(Method method) {
        String returnStatement = method.getReturnType().equals(void.class) ? "" : "return ";
        
        String args = Arrays.stream(method.getParameters()).map(Parameter::getName).collect(Collectors.joining(", "));

        return returnStatement + String.format("extension.%s(%s);\n", method.getName(), args);
    }
    
    /**
     * test if method has argument of type <code>Invocation</code>
     */
    private boolean hasInvocationArgument(Method method) {
        Class<?>[] pts = method.getParameterTypes();
        return Arrays.stream(pts).anyMatch(p -> CLASSNAME_INVOCATION.equals(p.getName()));
    }
    
    /**
     * generate code to test argument of type <code>Invocation</code> is null
     */
    private String generateInvocationArgumentNullCheck(Method method) {
        Class<?>[] pts = method.getParameterTypes();
        return IntStream.range(0, pts.length).filter(i -> CLASSNAME_INVOCATION.equals(pts[i].getName()))
                        .mapToObj(i -> String.format(CODE_INVOCATION_ARGUMENT_NULL_CHECK, i, i))
                        .findFirst().orElse("");
    }

    /**
     * get value of adaptive annotation or if empty return splitted simple name
     * Adaptive 注解值 value 类型为 String[]，可填写多个值，默认情况下为空数组。
     * 若 value 为非空数组，直接获取数组内容即可。
     * 若 value 为空数组，则需进行额外处理。
     * 处理过程是将类名转换为字符数组，然后遍历字符数组，并将字符放入 StringBuilder 中。
     * 若字符为大写字母，则向 StringBuilder 中添加点号，随后将字符变为小写存入 StringBuilder 中。
     * 比如 LoadBalance 经过处理后，得到 load.balance
     */
    private String[] getMethodAdaptiveValue(Adaptive adaptiveAnnotation) {
        String[] value = adaptiveAnnotation.value();
        // value is not set, use the value generated from class name as the key
        if (value.length == 0) {
            //type.getSimpleName()：Protocol 不是全路径org.apache.dubbo.rpc.Protocol
            //StringUtils.camelToSplitName是把驼峰标识的转换为用.分割

            String splitName = StringUtils.camelToSplitName(type.getSimpleName(), ".");
            value = new String[]{splitName};
        }
        return value;
    }

    /**
     * get parameter with type <code>URL</code> from method parameter:
     * <p>
     * test if parameter has method which returns type <code>URL</code>
     * <p>
     * if not found, throws IllegalStateException
     */
    private String generateUrlAssignmentIndirectly(Method method) {
        Class<?>[] pts = method.getParameterTypes();
        
        // find URL getter method
        // 遍历方法的参数类型列表
        for (int i = 0; i < pts.length; ++i) {
            // 获取某一类型参数的全部方法
            // 遍历方法列表，寻找可返回 URL 的 getter 方法
            for (Method m : pts[i].getMethods()) {
                String name = m.getName();
                // 1. 方法名以 get 开头，或方法名大于3个字符
                // 2. 方法的访问权限为 public
                // 3. 非静态方法
                // 4. 方法参数数量为0
                // 5. 方法返回值类型为 URL
                if ((name.startsWith("get") || name.length() > 3)
                        && Modifier.isPublic(m.getModifiers())
                        && !Modifier.isStatic(m.getModifiers())
                        && m.getParameterTypes().length == 0
                        && m.getReturnType() == URL.class) {
                    return generateGetUrlNullCheck(i, pts[i], name);
                }
            }
        }
        
        // getter method not found, throw
        throw new IllegalStateException("Failed to create adaptive class for interface " + type.getName()
                        + ": not found url parameter or url attribute in parameters of method " + method.getName());

    }

    /**
     * 1, test if argi is null
     * 2, test if argi.getXX() returns null
     * 3, assign url with argi.getXX()
     */
    private String generateGetUrlNullCheck(int index, Class<?> type, String method) {
        // Null point check
        StringBuilder code = new StringBuilder();
        // 为可返回 URL 的参数生成判空代码，格式如下：
        // if (arg + urlTypeIndex == null)
        //     throw new IllegalArgumentException("参数全限定名 + argument == null");
        code.append(String.format("if (arg%d == null) throw new IllegalArgumentException(\"%s argument == null\");\n",
                index, type.getName()));
        // 为 getter 方法返回的 URL 生成判空代码，格式如下：
        // if (argN.getter方法名() == null)
        //     throw new IllegalArgumentException(参数全限定名 + argument getUrl() == null);
        code.append(String.format("if (arg%d.%s() == null) throw new IllegalArgumentException(\"%s argument %s() == null\");\n",
                index, method, type.getName(), method));
        // 生成赋值语句，格式如下：
        // URL全限定名 url = argN.getter方法名()，比如
        // com.alibaba.dubbo.common.URL url = invoker.getUrl();
        code.append(String.format("%s url = arg%d.%s();\n", URL.class.getName(), index, method));
        return code.toString();
    }
    
}
