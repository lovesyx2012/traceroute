traceroute & ping in Python
===========================

I did this to learn more about raw sockets.


```
$ sudo ./traceroute.py 4.2.2.1
1 :  192.168.90.1
2 :  23.240.192.1
3 :  76.167.31.113
4 :  72.129.25.192
5 :  72.129.25.0
6 :  107.14.19.32
7 :  107.14.19.138
8 :  66.109.9.122
9 :  4.69.158.81
10 :  4.69.153.225
11 :  4.69.137.46
12 :  4.69.144.201
13 :  4.2.2.1
```


```
$ sudo ./ping.py 4.2.2.1
Reply from 4.2.2.1 echo_seq=0 time=34ms
Reply from 4.2.2.1 echo_seq=1 time=19ms
Reply from 4.2.2.1 echo_seq=2 time=19ms
Reply from 4.2.2.1 echo_seq=3 time=19ms
Reply from 4.2.2.1 echo_seq=4 time=17ms
Reply from 4.2.2.1 echo_seq=5 time=17ms
```
