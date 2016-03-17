0. errors

  1. /usr/local/jdk/bin/java: error while loading shared libraries: /usr/local/jdk1.7.0_80/bin/../lib/amd64/jli/libjli.so:
  file too short
  
  [root@tp-deal01 ~]# locate libjli.so
  /usr/lib/jvm/java-1.7.0-openjdk-1.7.0.45.x86_64/jre/lib/amd64/jli/libjli.so
  /usr/lib/jvm/java-1.7.0-openjdk-1.7.0.45.x86_64/lib/amd64/jli/libjli.so
  [root@tp-deal01 ~]#rm /usr/local/jdk1.7.0_80/lib/amd64/jli/libjli.so
  [root@tp-deal01 ~]#ln -s /usr/local/jdk1.7.0_80/jre/lib/amd64/jli/libjli.so /usr/local/jdk1.7.0_80/lib/amd64/jli/libjli.so 
