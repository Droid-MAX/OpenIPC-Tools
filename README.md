# OpenIPC-Tools

一些专为`OpenIPC`开发的小工具

## 都有哪些功能？

* `openipc-brute.py`: 登录凭据爆破，但指定主机列表参数使用时输出会混乱
* `openipc-cmd.py`: 远程命令执行，不建议执行`top`这类命令
* `openipc-download.py`: 文件下载，直接下载二进制文件会有问题
* `openipc-get.py`: 获取文本文件内容
* `openipc-upload.py`: 文件上传，不建议上传二进制文件

## 问题反馈

在使用中有任何问题，欢迎使用`issues`与我反馈

## 还有一件事

有关文件下载还可以使用其他方法，比如:

```
curl -s -H "Authorization: Basic YWRtaW46MTIzNDU=" http://192.168.123.9/cgi-bin/texteditor.cgi?f=/etc/passwd | htmlq -t .small
```
