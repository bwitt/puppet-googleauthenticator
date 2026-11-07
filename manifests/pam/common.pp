# == Class: googleauthenticator::pam::common
#
# Common PAM requirements for googleauthenticator.
#
# It shouldn't be necessary to directly include this class.
#
class googleauthenticator::pam::common {
  $package = $facts['os']['family'] ? {
    'Debian' => 'libpam-google-authenticator',
    'RedHat' => 'google-authenticator',
    default  => '',
  }

  $service = $facts['os']['family'] ? {
    'RedHat' => 'sshd',
    default  => 'ssh',
  }

  package { 'pam-google-authenticator':
    name => $package,
  }

  # Setup the three basic PAM modes
  googleauthenticator::pam::mode {
    'all-users':
      service => $service;

    'root-only':
      succeed_if => 'uid > 0',
      service    => $service;

    'systemwide-users':
      secret  => "/etc/google-authenticator/\${USER}/google_authenticator",
      service => $service;
  }
}
