# HAS Performance Test Report

## 1. Overview

HAS is a dedicated Hadoop authentication server to support various authentication mechanisms other than just Kerberos. With HAS users can remain their familiar login methods, and new authentication mechanism could be customized and plugined.  

A Hadoop cluster could have thousands of nodes, there maybe so many authentication  requests are sent to HAS server at the same time. So the stability in high concurrency is so important for HAS.

## 2. Test Environment

The test use Alibaba Cloud Elastic Compute Service, detailed test environment like the following: 

### 2.1 Hardware environment

* HAS Server:

> CPU：Intel(R) Xeon(R)CPU E5-2682 @ 2.50GHz    
> MEM: 16GB    
> Disk: 43GB 86GB    

* HAS Client:

> CPU：Intel(R) Xeon(R)CPU E5-2682 @ 2.50GHz    
> MEM: 16GB    
> Disk: 43GB 86GB * 3

### 2.2 Software environment

> OS: CentOS 7.2    
> JAVA: 1.8    
> HAS: 1.0.0    
> MySQL: 5.5.52  

## 3. Test Method

By using [login-test](https://github.com/Intel-bigdata/HAS/blob/master/has-dist/bin/login-test.sh) scripting tool, the test can be broadly divided into four steps:

1. Add principals to HAS server
2. Export keytab files to HAS Client  
    
    ```shell
    cd HAS/has-dist         
    sh bin/login-test add <conf_dir> <work_dir> <principal_num>
    ```

3. Use keytab files to login concurrently

    ```shell                        
    sh bin/login-test run <conf_dir> <work_dir> <concurrency_num>
    ```

4. Record login result and the cost time of login

Testing process like the following:

![testing process](https://user-images.githubusercontent.com/9171954/27905170-b7637602-6271-11e7-8fc9-27d494f9b1ee.jpg)

## 4. Test Result

The test result consists of total cost time and time per request of login using keytab file.

### 4.1 Using Json Backend

| Concurrency | 100 | 500 | 1000 | 5000 | 8000 | 10000 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Result | Success | Success  | Success  | Success | Success | Success |
| Total time (ms) | 540 | 1115 | 1661  | 4571 | 6328 | 7208 |
| Time per request (ms)| 5.400 | 2.230 | 1.661 | 0.914 | 0.791 | 0.721 |

### 4.2 Using MySQL Backend

MySQL Configuration：
> max connection: 5000              
> innodb buffer size: 8G

| Concurrency | 100 | 500 | 1000 | 5000 | 8000 | 10000 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Result | Success | Success  | Success  | Success | Success | Success |
| Total time (ms) | 765 | 2880  | 4821  | 12712 | 21419 | 22968 |
| Time per request (ms)| 7.650 | 5.760  | 4.821  | 2.542 | 2.677 | 2.297 |

## 5. Conclusion

![performance in different backends](https://user-images.githubusercontent.com/9171954/27905152-a9bc2a44-6271-11e7-8ddc-16222ee7d3c4.png)

Figure above demonstrates the time per request of HAS authentication in different backends and concurrency. As can be seen, HAS can complete authentication work in high concurrency, and has a good performance. So HAS is good enough for Hadoop.

The CPU utilization and network IO of HAS server are demonstrated in the appendix, with the number of concurrency up to 10000. The appendix shows that HAS server is not under heavy workload in mysql backend. 

## 6. Appendix

* CPU Utilization

![cpu utilization](https://user-images.githubusercontent.com/9171954/27905176-bf7ea410-6271-11e7-904e-abd1bf532725.jpg)

* Network IO

![network io](https://user-images.githubusercontent.com/9171954/27905186-c717b784-6271-11e7-96d3-2fd317defd96.jpg)
