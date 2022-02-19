#测试环境, 虚拟机信息

#测试描述
20480客户端连接127.0.0.1:6666
C发送4096字节数据到S
S回显数据到C

#time
real	5m51.078s
user	1m6.898s
sys	4m6.853s

#perf stat
26,459.60 msec cpu-clock                 #    2.000 CPUs utilized          
             2,169      context-switches          #    0.082 K/sec                  
                23      cpu-migrations            #    0.001 K/sec                  
                 2      page-faults               #    0.000 K/sec                  
   <not supported>      cycles                                                      
   <not supported>      instructions                                                
   <not supported>      branches                                                    
   <not supported>      branch-misses                                               

      13.228642142 seconds time elapsed

#perf top
   PerfTop:     926 irqs/sec  kernel:77.4%  exact:  0.0% lost: 0/0 drop: 0/0 [4000Hz cpu-clock],  (all, 2 CPUs)
-------------------------------------------------------------------------------

    13.31%  [kernel]            [k] copy_user_generic_unrolled
     6.49%  libc-2.17.so        [.] __memcpy_ssse3_back
     4.31%  [kernel]            [k] sock_poll
     3.98%  [kernel]            [k] sys_epoll_ctl
     3.60%  [kernel]            [k] __inet_lookup_established
     3.49%  libc-2.17.so        [.] epoll_ctl
     3.44%  [kernel]            [k] system_call_after_swapgs
     3.38%  [kernel]            [k] fget_light
     3.22%  libpthread-2.17.so  [.] __libc_recv
     2.51%  [kernel]            [k] clear_page
     2.29%  [kernel]            [k] _raw_spin_unlock_irqrestore
     1.91%  [kernel]            [k] sock_has_perm
     1.91%  libpthread-2.17.so  [.] __libc_send
     1.64%  [kernel]            [k] tcp_recvmsg
     1.42%  [kernel]            [k] sockfd_lookup_light
     1.31%  [kernel]            [k] SYSC_recvfrom
     1.25%  [kernel]            [k] tcp_poll
     1.20%  [kernel]            [k] vsnprintf
     0.93%  [kernel]            [k] _raw_spin_lock_bh
     0.93%  [kernel]            [k] kallsyms_expand_symbol.constprop.1



#cpuinfo
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Core(TM) i5-8600K CPU @ 3.60GHz
stepping	: 10
microcode	: 0xb4
cpu MHz		: 3600.002
cache size	: 9216 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc eagerfpu pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 invpcid rdseed adx smap clflushopt xsaveopt xsavec arat md_clear spec_ctrl intel_stibp flush_l1d arch_capabilities
bogomips	: 7200.00
clflush size	: 64
cache_alignment	: 64
address sizes	: 43 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 158
model name	: Intel(R) Core(TM) i5-8600K CPU @ 3.60GHz
stepping	: 10
microcode	: 0xb4
cpu MHz		: 3600.002
cache size	: 9216 KB
physical id	: 2
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc eagerfpu pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 invpcid rdseed adx smap clflushopt xsaveopt xsavec arat md_clear spec_ctrl intel_stibp flush_l1d arch_capabilities
bogomips	: 7200.00
clflush size	: 64
cache_alignment	: 64
address sizes	: 43 bits physical, 48 bits virtual
power management:

