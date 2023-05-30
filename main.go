package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type Config struct {
	WebsiteAddress        string `yaml:"website-address"`
	WesbiteSSHPort        string `yaml:"website-ssh-port"`
	WebsiteSSHHostKey     string `yaml:"website-ssh-host-key"`
	WebsiteMysqlContainer string `yaml:"website-mysql-container"`
	WebsiteMysqlRootPass  string `yaml:"website-mysql-root-pass"`
	SSHPublicKey          string `ya ml:"ssh-public-key-path"`
	SSHPrivateKey         string `yaml:"ssh-private-key-path"`
	SSHUser               string `yaml:"ssh-user"`
	BackupDestination     string `yaml:"backup-destination-path"`
}

var config Config
var sshConfig ssh.ClientConfig
var logger = log.New(os.Stdout, "seacow-daemon ", log.Ldate|log.Ltime|log.Lshortfile)

func main() {
	err := readConfig()
	handleErr(err, true)

	privateKey, err := readPrivateKey()
	handleErr(err, true)

	sshConfig = ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			privateKey,
		},
		Timeout:         5 * time.Second,
		HostKeyCallback: verifyHostKey,
	}

	var interrupt = make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	/*c := cron.New()
	c.AddFunc("@every week", runWebsiteBackup)
	c.Start()*/

	//First Run
	runWebsiteBackup()

	for {
		select {
		case interruptType := <-interrupt:
			logger.Println(interruptType.String())
			os.Exit(0)
		}
	}
}

func runWebsiteBackup() {
	logger.Println("Running Website Backup")

	conn, err := ssh.Dial("tcp", config.WebsiteAddress+":"+config.WesbiteSSHPort, &sshConfig)
	if err != nil {
		handleErr(fmt.Errorf("failed to dial: %w", err))
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		handleErr(fmt.Errorf("failed to create session: %w", err))
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err = copyMysqlCnf(conn); err != nil {
		handleErr(fmt.Errorf("failed to copy mysql cnf: %w", err))
	}

	t := time.Now()
	backupName := fmt.Sprintf("backup-%s-%s.tar.gz", t.Format("2006-01-02"), t.Format("15-04-05"))

	for i := range Commands {
		Commands[i] = strings.ReplaceAll(Commands[i], "__BACKUP_NAME__", backupName)
		Commands[i] = strings.ReplaceAll(Commands[i], "__CONTAINER_NAME__", config.WebsiteMysqlContainer)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		handleErr(fmt.Errorf("failed to create stdin pipe: %w", err))
	}

	if err = session.Start("/bin/bash"); err != nil {
		handleErr(fmt.Errorf("failed to start session: %w", err))
	}

	for _, command := range Commands {
		if _, err := fmt.Fprintf(stdin, "%s\n", command); err != nil {
			handleErr(fmt.Errorf("failed to write command to stdin: %w", err))
		}
	}

	logger.Println("Running Backup Commands")

	if err := stdin.Close(); err != nil {
		handleErr(fmt.Errorf("failed to close stdin: %w", err))
	}

	if err := session.Wait(); err != nil {
		handleErr(fmt.Errorf("failed to run cmd: %w", err))
	}

	logger.Println("Finished Running Backup Commands: ", stdoutBuf.String())

	logger.Println("Downloading Archive", backupName)

	if err = downloadArchive(conn, backupName); err != nil {
		handleErr(fmt.Errorf("failed to download archive: %w", err))
	}
}

func copyMysqlCnf(conn *ssh.Client) error {
	mysqlCnf := `[client]
user=root
password=`

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to open SFTP session: %w", err)
	}
	defer sftp.Close()

	remoteFile, err := sftp.Create("/server/backup-staging/backup.cnf")
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	bytesCopied, err := io.Copy(remoteFile, bytes.NewReader([]byte(mysqlCnf+config.WebsiteMysqlRootPass)))
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	logger.Println("Copied MySQL CNF:", bytesCopied, "bytes")

	return nil
}

func downloadArchive(conn *ssh.Client, backupName string) error {
	sftp, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to open SFTP session: %w", err)
	}
	defer sftp.Close()

	remoteFile, err := sftp.Open("/server/backup-archive/" + backupName)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer remoteFile.Close()

	// Create the local file for writing
	localFile, err := os.Create(config.BackupDestination + backupName)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()

	if _, err := remoteFile.WriteTo(localFile); err != nil {
		return fmt.Errorf("failed to copy remote file to local file: %w", err)
	}

	logger.Println("Finished Downloading", backupName)

	return nil
}

func handleErr(err error, fatal ...bool) {
	if err != nil {
		if len(fatal) > 0 && fatal[0] {
			logger.Fatal(err)
			os.Exit(1)
		} else {
			logger.Printf("%+v", err)
		}
	}
}

func readConfig() error {
	data, err := os.ReadFile("config.yml")
	if err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("error parsing config data: %w", err)
	}

	return nil
}

func readPrivateKey() (ssh.AuthMethod, error) {
	privateKeyBytes, err := os.ReadFile(config.SSHPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error reading ssh private key: %w", err)
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing ssh private key: %w", err)
	}

	return ssh.PublicKeys(privateKey), nil
}

func verifyHostKey(hostname string, remote net.Addr, receivedKey ssh.PublicKey) error {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.WebsiteSSHHostKey))
	if err != nil {
		return fmt.Errorf("failed to parse host key: %w", err)
	}

	if !bytes.Equal(hostKey.Marshal(), receivedKey.Marshal()) {
		return fmt.Errorf("host key mismatch for %s: got %s, want %s", hostname, receivedKey.Type(), hostKey.Type())
	}

	return nil
}
