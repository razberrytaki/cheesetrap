package sensorinput

type Credentials struct {
	Username string
	Password string
}

func InvalidSSHCredentials() Credentials {
	return Credentials{Username: "synthetic-invalid-user", Password: "synthetic-invalid-password"}
}
