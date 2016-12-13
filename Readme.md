# 加密算法Java实现
---

### 运行环境：
- jdk 1.8
- IntelliJ IDEA 2016.2

### 已实现加密算法：
- AES对称加密
- RSA非对称加密
- RSA签名
- ECIES非对称加密

### 所需库
- Bouncy Castle
- JUnit
以上.jar文件已存在`lib`文件夹中，具体导入项目方法请自行Google

### **注意**
Oracle公司由于各国政策原因，限制的部分加密算法的秘钥长度。
解除限制很简单：
将`JCEPolicyJDK8`文件夹中的`local_policy.jar`和`US_export_policy.jar`文件替换掉`${java_home}/jre/lib/security/`文件夹中的同名文件

若Mac用户无法定位 java home，可使用命令工具运行：`/usr/libexec/java_home`进行定位_ 
文件夹中jce文件仅适用于替换`jdk1.8`版本，其他版本请到Oracle官网下载：
jdk1.7：[http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
jdk1.6：[http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)