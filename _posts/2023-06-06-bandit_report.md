# 보고서

# **level0**

ssh bandit0@bandit.labs.overthewire.org -p 2220

- p 옵션을 생략하면 ssh 기본 포트인 22로 연결되기때문에 -p 옵션으로 포트를 지정합니다.

# **level0 -> level1**

Step 1. bandit0 계정으로 bandit 시스템에 접속합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 3. cat 명령어를 이용해 readme 파일을 읽습니다.

![Untitled](/assets/bandit_report/Untitled.png)

# **level1 -> level2**

Step 1. bandit0에서 알아낸 비밀번호로 bandit1을 로그인합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 3. cat 명령어를 이용해 - 파일을 읽는데 cat - 는 옵션으로 인식되어 현재 경로를 표시하는 ./를 붙여서 파일을 읽습니다.

![Untitled](/assets/bandit_report/Untitled%201.png)

---

# **level2 -> level3**

Step 1. bandit1에서 알아낸 비밀번호로 bandit2을 로그인합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 3. cat 명령어를 이용해 spaces in this filename 을 읽는데 띄어쓰기가 있어서 spaces, in, this, filename 각각 다른 파일로 인식하여 “”로 이름을 묶거나 \을 사용해서 파일을 읽습니다.

![Untitled](/assets/bandit_report/Untitled%202.png)

---

# **level3 -> level4**

Step 1. bandit2에서 알아낸 비밀번호로 bandit3을 로그인합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 3. inhere라는 디렉토리 파일이있어서 cd 명령어로 현재경로를 이동합니다.

Step 4. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인하는데 숨긴파일이여서 -a옵션을 사용합니다.

Step 5. cat 명령어로 .hidden 파일을 읽습니다.

![Untitled](/assets/bandit_report/Untitled%203.png)

---

# **level4 -> level5**

Step 1. bandit3에서 알아낸 비밀번호로 bandit4을 로그인합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인하고 cd 명령어를 통해 inhere 디렉토리로 이동합니다.

Step 3. ls 명령어롤 통해 현재 경로에 존재하는 파일을 확인했는데 사람이 읽을수 있는 파일을 찾기위해 file 명령어를 이용하여 파일 속성을 확인합니다.

Step 4. cat 명령어로 사람이 읽을수 있는 파일속성(ascii text)인 -file07을 읽습니다.

![Untitled](/assets/bandit_report/Untitled%204.png)

---

# **level5 -> level6**

Step 1. bandit4에서 알아낸 비밀번호로 bandit5을 로그인합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인하고 cd 명령어를 통해 inhere 디렉토리로 이동합니다.

Step 3. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인하는데 너무 많은 파일이 나와서 find 명령어를 이용해 해당파일을 찾습니다.(1. 사람이 읽을 수 있는 파일 2. 1033 바이트 크기 3. 실행 불가능한 파일)

Step 4. find 명령어를 이용해 2. 조건은 -size 옵션을 통해 해결하고 3. 조건은 -not -executable 1. 조건은 -exec file {} \;을 이용하여 파일을 찾습니다.

Step 5. Step 4.에서 찾은./maybehere07/.file2 파일을 cat 명령어를 통해 파일을 읽습니다.

![Untitled](/assets/bandit_report/Untitled%205.png)

---

# **level6 -> level7**

Step 1. bandit5에서 알아낸 비밀번호로 bandit6을 로그인합니다.

Step 2. 시스템 어딘가에 저장되어있는 (1. 사용자 bandit7 소유, 2. 그룹 bandit6 소유, 3. 33바이트 크기)파일을 찾기위해 find 명령어를 이용합니다.

Step 3. 사용자 bandit7 소유자를 찾기위해 user옵션을 사용하고 그룹 bnadit6은 -group 옵션 33바이트 크기는 아까 사용한 -size 옵션을 사용하여 파일을 찾는습니다.

(오류로 확인이 힘들어서 2>/dev/null 을 이용하여 오류를 안 나오게 했습니다.)

Step 4. Step 3. 에서 확인한 파일을 cat 명령어를 사용하여 읽습니다.

![Untitled](/assets/bandit_report/Untitled%206.png)

---

# **키워드 정리**

1. SSH (Secure Shell Protocol)
    1. 네트워크 상의 다른 컴퓨터에서 원격으로 명령을 실행 또는 파일을 복사할 수 있도록 해 주는 응용 프로그램 또는 프로토콜
    2. 기존의 telnet 등을 대체하기 위해 설계
    3. 기본 프로토콜은 22번을 사용
2. 리눅스 명령어 : ls, cd, cat, file, find
    1. ls (list segments) : 파일의 목록을 표시하는 기능을 수행하는 명령어
    2. cd (change directory) : 작업 중인 디렉터리의 위치를 바꾸는 명령어
        
        디렉터리의 위치변경에는 절대경로와 상대경로가 사용되며/home/user 는 절대경로 ./현재폴더 ../상위폴더 를 가리키는 상대경로이다.
        
    3. cat (concatenate(연결하다)의 동의 어인 catenate에서 유래)파일들을 연결하고 표시하기 위해 사용되는 프로그램
    4. file : 지정된 파일의 종류(타입)을 확인하는 명령어
    5. find : 파일 및 디렉토리를 검색할 때 사용하는 명령어
        
        리눅스 명령어에서 -(dash) 특수문자의 의미
        
        명령어의 옵션으로 사용
        

1. 리눅스파일
    1. 숨김 파일
        - 리눅스 숨김파일은 파일 이름이나 디렉토리의 제일 앞글자를 .으로 하면 숨김파일이 된다. ls 명령어 a 옵 션으로 볼수있다.
        - 리눅스 파일 타입
        - ls 명령어의 l 옵션을 사용하여 출력되는 화면에 첫 번째 문자에서 확인이 가능
    2. 일반 파일
        - 문자 -
        - 각종 텍스트파일, 실행 파일, 이미지 파일등 리눅스에서 사용하는 대부분의 파일
    3. 디렉토리 파일
        - 문자 d
        - 리눅스에서는 폴더도 파일로 취급
        - 디렉토리 파일은 다른 파일들의 목록을 가지고 있거나 그 파일들의 정보를(주소를) 가리키는 포인터들을 가지는 파일
    4. 심볼릭 링크
        - 문자 l
        - 원본 파일을 대신해 다른 이름으로 파일명을 지정한 것
        - 윈도우의 바로가기 파일과 비슷한 역할
    
    e. 리눅스 파일 권한(Permission)
    
    - 권한의 종류
        - read(읽기) : 파일을 읽을 수 있는 권한
        - write(쓰기) : 파일을 수정하거나, 쓰거나, 지울 수 있는 권한
        - execute(실행) : 파일을 실행할 수 있는 권한
        
    
    예시 : -rwxrw-r—
    
    <처음 나오는 -는 일반 파일이며 rwx 소유자 권한 rw- 그룹 권한 r— 나머지 사용자가 사용할수 있는권 한 이다.
    
    rwx 읽기쓰기실행을 다할 수 있으며, rw-는 읽기쓰기 ,r—는 읽기 권한만 가진다.
    
2. 리눅스 /etc/passwd 파일
    - 사용자 계정을 관리하는 파일
        - 1️⃣root:2️⃣x:3️⃣0:4️⃣0:5️⃣root:6️⃣/root:7️⃣/bin/bash
            - 1. 사용자명
            - 2. 패스워드 유무(/etc/shadow 파일에 암호화되어 있다)
            - 3. 사용자 계정 uid
            - 4. 사용자 그룹 gid
            - 5. 사용자 계정 이름(정보)
            - 6. 사용자 계정 홈 디렉토리
            - 7. 사용자 계정 로그인 쉘

# **level7 -> level8**

Step 1. bandit7 계정으로 bandit 시스템에 접속합니다.

Step 2. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 3. cat 명령어를 이용해 data.txt 파일을 읽습니다.

Step 4. | PIPE를 이용하여 millionth 단어가 있는 줄을 찾습니다.

![Untitled](/assets/bandit_report/Untitled%207.png)

---

# **level8 -> level9**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. sort 명령어와 uniq 명령어를 통해 한번만 작성된 문장을 찾습니다.

![Untitled](/assets/bandit_report/Untitled%208.png)

---

# **level9 -> level10**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. cat 명령어를 통해 data.txt을 실행합니다.

Step 3. 읽을수 없는 문자가 섞여있어서 strings 명령어를 통해 문자만 필터합니다.

Step 4. =뒤에 오는 문자말고는 의미가 없는거 같아 grep =을 통해 필터합니다.

![Untitled](/assets/bandit_report/Untitled%209.png)

---

# **level10 -> level11**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. cat 명령어를 통해 data.txt을 실행합니다.

Step 3. base64로 인코딩되어 있어서 base64 명령어를 통해 디코딩 합니다.

![Untitled](/assets/bandit_report/Untitled%2010.png)

---

# **level11 -> level12**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. cat 명령어를 통해 data.txt을 실행합니다.

Step 3. rot13 카이사르 암호로 되어있어 tr 명령어를 통해 원래대로 돌려줍니다.

![Untitled](/assets/bandit_report/Untitled%2011.png)

---

# **level12 -> level13**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. mkdir 명령어를 통해 /tmp/test111 디렉토리를 만들고 cp 명령어를 통해 파일을 복사합니다.

Step 3. file 명령어를 통해 어떤 파일인지 확인합니다.

Step 4. gzip, bzip2 압축파일은 이름뒤에 .gz , bz2 가 있어야 해서 mv 명령어를 통해서 이름을 변경합니다.

Step 5. tar 압축 파일도 섞여있어서 옵션 -xvf 을 통해서 압축을 해제해 주고 3-5Step 을 반복합니다.

Step 6. file 명령어를 통해 ASCII text 파일임을 확인하고 cat 명령어를 통해 실행합니다.

![Untitled](/assets/bandit_report/Untitled%2012.png)

---

# **level13 -> level14**

Step 1. ls 명령어를 통해 현재 경로에 존재하는 파일을 확인 합니다.

Step 2. sshkey.private 복사하여 로그아웃 합니다.

Step 3. sshkey.private 사용하여 bandit14 에 로그인합니다.

Step 4. ssh bandit14@bandit.labs.overthewire.org -i ./sshkey.private -p 2220

![https://cafeptthumb-phinf.pstatic.net/MjAyMTA3MDJfNzMg/MDAxNjI1MjA4NjQ5NTU3.W2fqBySZ3oFFrAZEGmoKUVoQcvpFB2tZBkOpqib9L34g.5gtxkNeJluayIkiBaTNJAPMLFfw-qQDNk3NidDKNDoEg.PNG/random_818B9A04-F8E1-4881-81C2-3C51235BC587.png?type=w1600](https://cafeptthumb-phinf.pstatic.net/MjAyMTA3MDJfNzMg/MDAxNjI1MjA4NjQ5NTU3.W2fqBySZ3oFFrAZEGmoKUVoQcvpFB2tZBkOpqib9L34g.5gtxkNeJluayIkiBaTNJAPMLFfw-qQDNk3NidDKNDoEg.PNG/random_818B9A04-F8E1-4881-81C2-3C51235BC587.png?type=w1600)

---

# **키워드 정리**

1. 리눅스 명령어
    1. grep은 입력으로 전달된 파일의 내용에서 특정 문자열을 찾고자할 때 사용하는 명령어 입니다.
    2. sort는 사용자가 지정한 파일의 내용을 정렬하거나 정렬된 파일의 내용을 병합할 때 사용한다.
    3. uniq는 입력 내용에서 추가 된 항목을 제거하는 단일 라인 유틸리티입니다.
    4. strings 명령어는 실행파일의 ASCII 문자를 찾아 화면에 출력합니다.

1. base64란? 8비트 이진 데이터(에: 실행 파일, zip 파일 등)를 문자 코드에 영향을 받지 않는 공통 ASCII 영 역의 문자열로 바꾸는 인코딩 방식을 가리키는 개념입니다.
    1. base64 명령어는 문자열을 base64로 인코딩 또는 디코딩 해주는 명령어 입니다.

1. tr는 지정한 문자를 변환하거나 삭제하는 명령어입니다. 특정한 문자를 다른 문자로 변환하거나 특정 문자를 제거하는데 사용되는 명령어입니다.
    1. tar는 여려 개의 파일을 하나의 파일로 묶거나 풀 때 사용하는 명령어입니다. (테이프 아카이버(Tape ARchiver)의 앞 글자들을 조합하여 “tar”라는 이름으로 되었습니다.)

1. 리눅스 PIPE 개념
    1. 파이프(Pipe)란 2개의 프로세스를 연결해주는 연결 통로를 의미합니다.
    2. '|'문자를 사용하여 두 명령어를 연결해 주면 앞에서 실행한 출력값을 뒤에 적은 명령의 입력으로 사용합니다.

1. 인코딩/디코딩 개념
    1. 코드를 컴퓨터에 저장하거나 통신목적에 맞는 형식으로 변환하는 작업을 인코딩이라고 하며 반대의 역활을 하는것을 디코딩이라고 한다.

1. 아스키 코드
    1. ASCII(미국정보교환표준부호)는 영문 알파벳을 사용하는 대표적인 문자 인코딩입니다.

1. ssh key
    1. 비밀번호 없이 ssh 로그인하는 방법은 ssh key(서버에 접속 할 때 비밀번호 대신 key를 제출하는 방식)을 사용합니다.
    2. ssh key는 공개키와 비공개 키로 이루어져있고 공개 키는 서버에 비공개 키는 클라이언트에 위치하며 ssh 접속을 시도하면 ssh client가 로컬 머신의 비공개키와 원격 머신의 비공 개 키를 비교해서 둘이 일치하면 로 그인이 됩니다.

[data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMzEzIiBoZWlnaHQ9IjY5NiIgdmlld0JveD0iMCAwIDEzMTMgNjk2Ij48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjRkNGQ0ZDIi8+PC9zdmc+](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMzEzIiBoZWlnaHQ9IjY5NiIgdmlld0JveD0iMCAwIDEzMTMgNjk2Ij48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjRkNGQ0ZDIi8+PC9zdmc+)

# **level14 -> level15**

Step 1. cat /etc/bandit_pass/bandit14 를 통해 현재 비밀번호를 확인합니다.

Step 2. nc 명령어를 통해 [localhost](http://localhost)(ip : 127.0.0.1) port : 30000 에 접속합니다.

Step 3. 현재 비밀번호를 입력하면 level15 비밀번호가 출력됩니다.

![Untitled](/assets/bandit_report/Untitled%2013.png)

**level15 -> level16**

Step 1. SSL 통신을 위해 openssl 명령어를 사용합니다.(openssl s_client localhost:30001)

Step 2. 현재 비밀번호를 입력하면 level16 비밀번호가 출력됩니다.

![bandit15_1.png](/assets/bandit_report/bandit15_1.png)

![Untitled](/assets/bandit_report/Untitled%2014.png)

# **level16 -> level17**

Step 1. 31000부터 32000까지 일일히 접속하는 것은 비효율 적입니다. 그래서 nmap을 이용해 포트스캐닝을 진행합니다.

![Untitled](/assets/bandit_report/Untitled%2015.png)

Step 2. 5개의 포트가 나왔고 openssl s_client 명령어를통해 통신합니다. 

![bandit16_2.png](/assets/bandit_report/bandit16_2.png)

![Untitled](/assets/bandit_report/Untitled%2016.png)

# **level17 -> level18**

Step 1. 문제 설명에 따라서 [passwords.](http://passwords.new)old 와 [passwords.new](http://passwords.new) 파일의 비교하는 diff 명령어를 사용합니다.

Step 2. old → new 로 변경된 줄이 나왔고 해당 문자열이 플래그입니다. 

![Untitled](/assets/bandit_report/Untitled%2017.png)

# **level17 -> level18**

Step 1. level17에 접속하니 명령어를 입력하기도 전에 종료되도록 되어 있었습니다.

Step 2. 접속하는 동시에 명령어를 실행 시킬 방법을 찾다가 ssh 옵션중 마지막에 명령어를 적으면 해당 명령어를 실행한다는 사실을 알게되었습니다.

Step 3. ssh 접속과 동시에 cat ./readme 파일을 읽어서 해당 플래그를 찾았습니다.

![bandit18_1.png](/assets/bandit_report/bandit18_1.png)

![Untitled](/assets/bandit_report/Untitled%2018.png)

# **level18 -> level19**

Step 1. setuid 권한이  걸린 파일이 있었고 해당파일을 실행해보니 다른 명령어를 실행시킬수 있다는 사실을 알게되었습니다. 

Step 2. 즉 bandit20의 권한으로 명령어를 실행 시킬수 있고 cat 명령어를 통해 bandit20 의 플래그를 획득 하였습니다.

![Untitled](/assets/bandit_report/Untitled%2019.png)

# **level20 -> level21**

Step 1. suconnect 프로그램을 실행시켜보면 정확한 비밀번호를 받으면  다음 비밀번호를 받는다는 것을 알수 있습니다.

Step 2. nc 명령어를 사용하여 33334 포트를 열여주고 suconnect를 사용하여 접속합니다.

Step 3. bandit20 비밀번호를 입력하면 bandit21 비밀번호를 받을수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2020.png)

![Untitled](/assets/bandit_report/Untitled%2021.png)

# **키워드 정리**

1. nc : netcat의 줄인 말로 TCP또는 UDP를 사용하여 네트워크 연결을 읽거나 기록하는 컴퓨터 네트워킹 유틸리티 
    - 서버 : nc -lvnp <포트번호>
    - 클라이언트 : nc <IP/FQDN> <포트번호>

| 옵션 | 설명 |
| --- | --- |
| -n | 호스트 네임과 포트를 숫자로만 입력 |
| -v | 상세한 정보를 출 |
| -o | 주고 받는 데이터를 헥스덤프하여 파일로 저장  |
| -u | UDP 연결 |
| -p | local port 지 |
| -s | IP주소 지정 |
| -l | listen 모드로 port 오픈 |
| -z | 최소한의 데이터로 포트 스캔 |

1. SSL 보안 소켓 계층(Secure Sockets Layer, SSL)은 웹사이트와 브라우저 사이(또는 두 서버 사이)에 전송되는 데이터를 암호화하여 인터넷 연결을 보호하기 위한 표준 기술
2. openssl : TLS/SSL 통신을 하기 위한 오픈소스 라이브러리입니다.

1. Nmap(network mapper)  보안 스캐너이고 컴퓨터와 서비스를 찾을 때 쓰이며, 서비스 탐지 프로토콜로 자신을 광고하지 않는 수동적인 서비스들도 찾아낼 수 있다.  

| 옵션 | 설명 |
| --- | --- |
| -p (port) | 특정 포트를 지정(1,2,3 // 1-3 // -p- 모든 포트) |
| -sV (Service Version info) | 포트에 실행중인 서비스의 배너를 가져옴 |
| -sC (Service Script) | 서비스를 대상으로 기본(default) nmap 스크립트를 실행 |
| -o (output) | 출력결과가 들어간 파일 지정 |
| -T (Timing template) | 스캔의 속도 지정 |
| -sn (Ping Scan) | 포트스캔을 진행하지 않고 핑 스캔만 진행 |
| -Pn (ignore Ping scan) | 핑 스캔 및 호스트 발견을 진행하지 않고 포트스캔만 진행 |
| -O (Os detection) | 대상의 운영체제 추측 |

1. Diff는 두 개의 파일 간 차이에 대한 정보를 출력하는 파일 비교 유틸리티이다. 대부분 ‘diff a.txt b.txt’ 와 같이 2개의 파일을 비교합니다.

1. SetUID는 유닉스 환경에서 일시적으로 접근권한이 없는 파일에 접근을 허용하는 특수권한을 부여합니다. SetUID가 적용된 대표적인 사례는 계정의 비밀 번호를 변경 또는지정한 명령어인 ‘passwd’에 사용됩니다. 

# **level21 -> level22**

**Step 1.** 로그인 후 /etc/cron.d 에서 어떤 cronjob이 있는지 살펴 보면 bandit22 유저의 cronjob이 있습니다. * * * * *인 것을 보아 ‘/usr/bin/cronjob_bandit22.sh’ 이 실행 되고 있습니다.

![Untitled](/assets/bandit_report/Untitled%2022.png)

**Step 2.** /usr/bin/cronjob_bandit22.sh을 cat 파일로 열어보니 bindit22의 비밀번호가 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv여기에 저장되는걸 볼수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2023.png)

**Step 3.** /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv 파일을 cat 명령어로 출해보면 플래그를 획득할수 있습니다. 

# **level22 -> level23**

Step 1. 다시 cronjob이 있는지 살펴 보면 bandit23 유저의 cronjob이 있습니다. ‘/usr/bin/cronjob_bandit23.sh’을 출력해보니 shell script 동작하고 있습니다.

![Untitled](/assets/bandit_report/Untitled%2024.png)

Step 2. 해당 스크립트를 분석해보면 myname에 user name이 들어가고 md5sum 해시를 이용해 파일이 만들어 집니다.

![Untitled](/assets/bandit_report/Untitled%2025.png)

Step 3. bandit23 유저의 변수를만드는 부분만 출력하여 해당 파일을 출력합니다. 

# **level23 -> level24**

Step 1. 스크립트를 보면 /var/spool/$myname/foo 위치에서 모든 파일을 실행 후 삭제하는 사실을 알 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2026.png)

Step 2. cp 명령어를 이용하여 /var/spool/bandit24/foo/a.sh 에 파일을 복사합니다.

![Untitled](/assets/bandit_report/Untitled%2027.png)

Step 3. 파일이 실행되면 bandit24 파일이 생성되고 해당 파일에 플래그가 담긴 것을 확인할 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2028.png)

# **level24 -> level25**

Step 1. 포트 30002에서 데몬이 실행 중이며 bandit24에 대한 패스워드와 pin 코드 4자리가 맞을 경우 bandit25에 대한 패스워드를 알려줍니다. nc로 연결한 결과 한 개씩 대입하기 사실상 힘들기 때문에 쉘 스크립트를 작성합니다.

![Untitled](/assets/bandit_report/Untitled%2029.png)

```bash
#!/bin/bash
for i in {0000..9999}
do
echo "VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar $i"
done | nc localhost 30002 | grep -v "Wrong"

```

grep -v 옵션으로 “Wrong” 가 들어가있는 라인 무시

![Untitled](/assets/bandit_report/Untitled%2030.png)

![Untitled](/assets/bandit_report/Untitled%2031.png)

처음에 sh로 실행할 때 for 문이 제대로 실행이 안 되어서 삽질하다가 bash로 실행하면 실행된다는 사실을 알게 됨

Step 2. 해당 스크립트 실행 결과 bandit25 패스워드를 획득했습니다.

![Untitled](/assets/bandit_report/Untitled%2032.png)

# **level25 -> level26**

Step 1. 로그인을 하면 bandit26의 개인키를 얻을 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2033.png)

Step 2. bandit26에 로그인하기 전에 /bin/bash 쉘이 아니라고 했으니 어떤 쉘인지 확인합니다.

![Untitled](/assets/bandit_report/Untitled%2034.png)

![Untitled](/assets/bandit_report/Untitled%2035.png)

![Untitled](/assets/bandit_report/Untitled%2036.png)

more 명령어를 통해 text.txt 파일을 출력 후 자동으로 종료되는 쉘입니다.  

![Untitled](/assets/bandit_report/Untitled%2037.png)

more 명령어에서 파일이 전부 출력되기 전에는 v를 누르면 vim 모드로 들어갈 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2038.png)

set shell 명령어를 통해 shell 을 변경해 줍니다.

![Untitled](/assets/bandit_report/Untitled%2039.png)

변경된 쉘을 실행하면 bandit26에 접속할 수 있습니다. 

# **키워드 정리**

1. cron
    - Cron/Cronjob 특정한 시간에 특정한 작업을수행하게 해주는 스케줄링 역활을 합니다.
    - cronjob들은 Crontab 파일을 통해 지정할 수 있습니다.

- 분(0-59)    시간(0-23)    일(1-31)    월(1-12)    요일(1-7) 7이나 0은 일요일을 가리킴    실행할 명령어
    
    ‘*’ 특수 기호는 매 분, 매 시간, 매일, 매달, 7일을 지정하는 특수기호 입니다.
    
    - 예) * * * * * echo “hello” > /tmp/Hi.txt 와 같은 crontab은 매분, 매일, 매달, 1주일 내내 명령어를 실행합니다.

1. Linux 데몬
    - 리눅스 시스템이 처음 가동될 때 실행되는 프로세스의 일종, 사용자의 요청을 기다리고있다가 요청이 발생하면 해당 서비스를 실행해 주는 역활을 한다. MS윈도우의 서비스(Service)와 비슷하고 실제로 “서비스”라고 부르기도 한다. 데몬 프로그램의 명령어는 ‘d’로 끝난다.(예 : ftpd, mysqld, httpd…)

1. Brute Force
    - 키 전수조사라고도 하는 무차별 암호 대입 공격은 무작위로 계속해서 입력함으로써 사용하는 공격방법입니다. 예를 들어 PIN 번호가 4자릿수라고 할때 0000, 0001, 0002, …. 9999 까지 모두 시도해 공격을 진행합니다.

# **level26 -> level27**

Step 1. 로그인 후 홈 디렉터리에 ‘bandit27-do’ 파일이 있습니다. 해당 파일에 setuid가 걸려있고 명령어를 실행시킬 수 있다는 사실을 알 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2040.png)

![Untitled](/assets/bandit_report/Untitled%2041.png)

Step 2. ‘bandit27-do’를 통해 id 명령어를 실행시키면 euid가 bandit27로 나오는 걸 알 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2042.png)

Step 3. ‘bandit27-do’를 통해 cat 명령어를 실행해서 bandit27의 패스워드를 알 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2043.png)

# **level27 -> level28**

Step 1. git clone 명령어를 통해서 git에 있는 파일을 다운합니다. 

Step 2. README라는 파일이 있고 출력하면 패스워드가 나옵니다.

![Untitled](/assets/bandit_report/Untitled%2044.png)

![Untitled](/assets/bandit_report/Untitled%2045.png)

# **level28 -> level29**

Step 1. 전 단계와 마찬가지로 파일을 다운받아 README를 출력합니다.

![Untitled](/assets/bandit_report/Untitled%2046.png)

Step 2. 패스워드가 가려져 있으니 commit 을 할때 실수로 패스워드를 올린 기록이 있는지 확인합니다. 

![Untitled](/assets/bandit_report/Untitled%2047.png)

Step 3. 잘못 올린 데이터를 위에서 수정하였으니 수정하기 전으로 checkout을 통해 변경해 줍니다. 그 후 다시 readme를 출력해 보면 패스워드가 나오는 것을 알 수 있습니다.

![Untitled](/assets/bandit_report/Untitled%2048.png)

![Untitled](/assets/bandit_report/Untitled%2049.png)

# **level29 -> level30**

Step 1.  전 단계와 마찬가지로 git clone을 해주고 readme 파일을 출력합니다.

![Untitled](/assets/bandit_report/Untitled%2050.png)

Step 2. 패스워드가 없는것을 확인하고 log -p 명령어를 사용해 변경된 부분이 어떤 부분이 있는지 확인했지만 패스워드는 나오지 않습니다.

![Untitled](/assets/bandit_report/Untitled%2051.png)

Step 3. 브런치가 어떤것이 있는지 확인후 dev 연결합니다.

![Untitled](/assets/bandit_report/Untitled%2052.png)

![Untitled](/assets/bandit_report/Untitled%2053.png)

Step 4. log -p 명령어를 통해 변경부분을 확인결과 패스워드가 출력되었습니다.

![Untitled](/assets/bandit_report/Untitled%2054.png)

# **키워드 정리**

1. git은 컴퓨터 파일의 변경사항을 추적하고 여러 명의 사용자들 간에 해당 파일들의 작업을 조율하기 위한 분산 버전 관리 시스템입니다.
    1. .git 명령어

| 명령어 이름 | 설명 |
| --- | --- |
| config | 유저이름이나 이메일 등을 설정합니다. |
| clone | 원격 저장소에 있는 코드를 내 컴퓨터에 복제합니다.  |
| add | 파일을 새로 추적할 때도 사용하고 수정한 파일을 Staged상태로 만들 때도 사용합니다.  |
| commit -m | 프로젝트의 현재상태를 나타내는 체크포인트 또는 스냅샷입니다.  |
| push | 원격 저장소로 업로드 할때 사용하는 명령어입니다. |
| pull | 원격 저장소에서 최신 데이터를 복제하여 내 컴퓨터에 가져옵니다. |
| checkout | 코드 저장소(repository)에서 특정 branch로 전환하는 작업을합니다. |
| status | 파일의 상태를 확인할 수 있습니다.  |
| log | 다양한 커밋 내역을 시간 순서대로 확인합니다. |
| branch -a | 로컬/리모트 저장소의 모든 branch 정보를 보여줍니다. |
| remote add | URL을 이용하여 원격 저장소를 지정합니다. |

# **level30 -> level31**

Step 1. README 파일을 출력해 보면 별다른 정보는 있지 않습니다.

![Untitled](/assets/bandit_report/Untitled%2055.png)

Step 2. status, branch, log 에서도 다른 정보가 있지 않습니다.

![Untitled](/assets/bandit_report/Untitled%2056.png)

Step 3. 마지막으로 tag라는 것이 있는데 특정 커밋을 표시하기 위한 기능입니다. ‘tag’ 명령어를 통해 secret 이 있는 것을 확인할 수 있고 ‘show secret’으로 플래그를 획득합니다.

![Untitled](/assets/bandit_report/Untitled%2057.png)

# **level31 -> level32**

Step 1. 이번에도 역시 README 파일을 출력해보면 아래 사항으로 파일을 원격서버에 push 하라고 나옵니다.

![Untitled](/assets/bandit_report/Untitled%2058.png)

Step 2. 설명대로 내용을 저장해서 key.txt 파일을 만들고 저장합니다.

![Untitled](/assets/bandit_report/Untitled%2059.png)

Step 3. ‘git add’ 명령어를 사용해 보니. gitignore 규칙에 적용되는 파일이 있어 파일을 추가할 수 없다고 나옵니다.

![Untitled](/assets/bandit_report/Untitled%2060.png)

Step 4. 위에 hint에서 나온 것처럼 -f 옵션을 붙여서 add를 하면 추가가 됩니다. 그리고 파일을 commit 하고 push 하면 플래그가 출력됩니다.

![Untitled](/assets/bandit_report/Untitled%2061.png)

![Untitled](/assets/bandit_report/Untitled%2062.png)

# **level32 -> level33**

Step 1. 로그인 후 명령어를 적어보니 위에 적힌 대로 대문자로 실행이 됩니다. 하지만 sh : 오류가 나오는 거 보니 sh에서 돌아가고 있는 거 같습니다.

![Untitled](/assets/bandit_report/Untitled%2063.png)

Step 2. 스크립트를 실행시킬 때 프로그램의 이름이 포함된 첫 번째 문자열을 저장하는 $0 변수를 실행시키면 $0에 sh 을 담고 있어서 sh 쉘이 실행됩니다.

![Untitled](/assets/bandit_report/Untitled%2064.png)

![Untitled](/assets/bandit_report/Untitled%2065.png)

# level33

![Untitled](/assets/bandit_report/Untitled%2066.png)