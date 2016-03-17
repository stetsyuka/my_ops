        yum install -y make gcc  openssl-devel pcre-devel  bzip2-devel libxml2 libxml2-devel curl-devel libmcrypt-devel libjpeg libjpeg-devel libpng libpng-devel openssl

        groupadd nginx
        useradd nginx -g nginx -M -s /sbin/nologin
        
        mkdir -p /opt/nginx-tmp

        wget http://labs.frickle.com/files/ngx_cache_purge-1.6.tar.gz
        tar fxz ngx_cache_purge-1.6.tar.gz
        # ngx_cache_purge 清除指定url缓存
        # 假设一个URL为 http://192.168.12.133/test.txt 
        # 通过访问      http://192.168.12.133/purge/test.txt  就可以清除该URL的缓存。
        
        tar zxvpf nginx-1.4.4.tar.gz
        cd nginx-1.4.4

        # ./configure --help
        # --with                 # 默认不加载 需指定编译此参数才使用
        # --without              # 默认加载，可用此参数禁用
        # --add-module=path      # 添加模块的路径
        # --add-module=/opt/ngx_module_upstream_check \         # nginx 代理状态页面  
        # ngx_module_upstream_check  编译前需要打对应版本补丁 patch -p1 < /opt/nginx_upstream_check_module/check_1.2.6+.patch
        # --add-module=/opt/ngx_module_memc \                   # 将请求页面数据存放在 memcached中
        # --add-module=/opt/ngx_module_lua \                    # 支持lua脚本 yum install lua-devel lua

        ./configure \
        --user=nginx \
        --group=nginx \
        --prefix=/usr/local/nginx \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --add-module=/opt/ngx_cache_purge-1.6 \
        --http-client-body-temp-path=/opt/nginx-tmp/client \
        --http-proxy-temp-path=/opt/nginx-tmp/proxy \
        --http-fastcgi-temp-path=/opt/nginx-tmp/fastcgi \
        --http-uwsgi-temp-path=/opt/nginx-tmp/uwsgi \
        --http-scgi-temp-path=/opt/nginx-tmp/scgi

        make && make install

        /usr/local/nginx/sbin/nginx –t             # 检查Nginx配置文件 但并不执行
        /usr/local/nginx/sbin/nginx -t -c /opt/nginx/conf/nginx.conf  # 检查Nginx配置文件
        /usr/local/nginx/sbin/nginx                # 启动nginx
        /usr/local/nginx/sbin/nginx -s reload      # 重载配置
        /usr/local/nginx/sbin/nginx -s stop        # 关闭nginx服务

    }

    httpd{

        编译参数{

            # so模块用来提供DSO支持的apache核心模块
            # 如果编译中包含任何DSO模块，则mod_so会被自动包含进核心。
            # 如果希望核心能够装载DSO，但不实际编译任何DSO模块，则需明确指定"--enable-so=static"

            ./configure --prefix=/usr/local/apache --enable-so --enable-mods-shared=most --enable-rewrite --enable-forward  # 实例编译

            --with-mpm=worker         # 已worker方式运行
            --with-apxs=/usr/local/apache/bin/apxs  # 制作apache的动态模块DSO rpm包 httpd-devel  #编译模块 apxs -i -a -c mod_foo.c
            --enable-so               # 让Apache可以支持DSO模式
            --enable-mods-shared=most # 告诉编译器将所有标准模块都动态编译为DSO模块
            --enable-rewrite          # 支持地址重写功能
            --enable-module=most      # 用most可以将一些不常用的，不在缺省常用模块中的模块编译进来
            --enable-mods-shared=all  # 意思是动态加载所有模块，如果去掉-shared话，是静态加载所有模块
            --enable-expires          # 可以添加文件过期的限制，有效减轻服务器压力，缓存在用户端，有效期内不会再次访问服务器，除非按f5刷新，但也导致文件更新不及时
            --enable-deflate          # 压缩功能，网页可以达到40%的压缩，节省带宽成本，但会对cpu压力有一点提高
            --enable-headers          # 文件头信息改写，压缩功能需要
            --disable-MODULE          # 禁用MODULE模块(仅用于基本模块)
            --enable-MODULE=shared    # 将MODULE编译为DSO(可用于所有模块) 
            --enable-mods-shared=MODULE-LIST   # 将MODULE-LIST中的所有模块都编译成DSO(可用于所有模块) 
            --enable-modules=MODULE-LIST       # 将MODULE-LIST静态连接进核心(可用于所有模块)
            
            # 上述 MODULE-LIST 可以是:
            1、用引号界定并且用空格分隔的模块名列表  --enable-mods-shared='headers rewrite dav'
            2、"most"(大多数模块)  --enable-mods-shared=most 
            3、"all"(所有模块)

        }

        转发{

            #针对非80端口的请求处理
            RewriteCond %{SERVER_PORT} !^80$
            RewriteRule ^/(.*)         http://fully.qualified.domain.name:%{SERVER_PORT}/$1 [L,R]

            RewriteCond %{HTTP_HOST} ^ss.aa.com [NC]
            RewriteRule  ^(.*)  http://www.aa.com/so/$1/0/p0?  [L,R=301]
            #RewriteRule 只对?前处理，所以会把?后的都保留下来
            #在转发后地址后加?即可取消RewriteRule保留的字符
            #R的含义是redirect，即重定向，该请求不会再被apache交给后端处理，而是直接返回给浏览器进行重定向跳转。301是返回的http状态码，具体可以参考http rfc文档，跳转都是3XX。
            #L是last，即最后一个rewrite规则，如果请求被此规则命中，将不会继续再向下匹配其他规则
