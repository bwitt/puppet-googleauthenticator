# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'googleauthenticator' do
  let(:ssh_service) { (fact('os.family') == 'RedHat') ? 'sshd' : 'ssh' }
  let(:pam_include) { (fact('os.family') == 'RedHat') ? 'auth\s+include\s+' : '@include ' }

  context 'with PAM and users' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
        <<~PUPPET
          service { '#{ssh_service}': }

          googleauthenticator::pam { ['login', 'su']:
            mode => 'root-only',
          }

          googleauthenticator::pam::mode { 'optional-users':
            succeed_if => 'uid > 1000',
            nullok     => true,
            service    => '#{ssh_service}',
          }

          include googleauthenticator::sshd

          googleauthenticator::user { 'root':
            secret_key    => 'C6SSDFBBH6P76EDM',
            scratch_codes => ['78905638', '14036415'],
          }

          user { 'gauser':
            ensure     => present,
            managehome => true,
          }

          googleauthenticator::user::systemwide { 'gauser-systemwide':
            user           => 'gauser',
            secret_key     => 'JBSWY3DPEHPK3PXP',
            disallow_reuse => false,
            require        => User['gauser'],
          }
        PUPPET
      end
    end

    describe package((fact('os.family') == 'RedHat') ? 'google-authenticator' : 'libpam-google-authenticator') do
      it { is_expected.to be_installed }
    end

    describe file('/etc/pam.d/google-authenticator-all-users') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to eq("auth required pam_google_authenticator.so\n") }
    end

    describe file('/etc/pam.d/google-authenticator-root-only') do
      its(:content) { is_expected.to eq("auth sufficient pam_succeed_if.so quiet uid > 0\nauth required pam_google_authenticator.so\n") }
    end

    describe file('/etc/pam.d/google-authenticator-systemwide-users') do
      its(:content) { is_expected.to eq("auth required pam_google_authenticator.so secret=/etc/google-authenticator/${USER}/google_authenticator\n") }
    end

    describe file('/etc/pam.d/google-authenticator-optional-users') do
      its(:content) { is_expected.to eq("auth sufficient pam_succeed_if.so quiet uid > 1000\nauth required pam_google_authenticator.so nullok\n") }
    end

    %w[login su].each do |service|
      describe file("/etc/pam.d/#{service}") do
        its(:content) { is_expected.to match(%r{^#{pam_include}google-authenticator-root-only$}) }
      end
    end

    describe file('/etc/ssh/sshd_config') do
      its(:content) { is_expected.to match(%r{^PasswordAuthentication yes$}) }
      its(:content) { is_expected.to match(%r{^ChallengeResponseAuthentication yes$}) }
      its(:content) { is_expected.to match(%r{^UsePAM yes$}) }
    end

    describe command('sshd -t') do
      its(:exit_status) { is_expected.to eq 0 }
    end

    describe file('/root/.google_authenticator') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 400 }
      it { is_expected.to be_owned_by 'root' }
      it { is_expected.to be_grouped_into 'root' }
      its(:content) { is_expected.to match(%r{\AC6SSDFBBH6P76EDM\n" RATE_LIMIT 3 30\n" WINDOW_SIZE 17\n" DISALLOW_REUSE\n" TOTP_AUTH\n78905638\n14036415\n+\z}) }
    end

    describe file('/etc/google-authenticator/gauser') do
      it { is_expected.to be_directory }
      it { is_expected.to be_mode 700 }
      it { is_expected.to be_owned_by 'gauser' }
    end

    describe file('/etc/google-authenticator/gauser/google_authenticator') do
      it { is_expected.to be_file }
      it { is_expected.to be_mode 400 }
      it { is_expected.to be_owned_by 'gauser' }
      it { is_expected.to be_grouped_into 'gauser' }
      its(:content) { is_expected.to start_with("JBSWY3DPEHPK3PXP\n\" RATE_LIMIT 3 30\n\" WINDOW_SIZE 17\n") }
      its(:content) { is_expected.not_to include('DISALLOW_REUSE') }
    end
  end

  context 'with PAM and users absent' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
        <<~PUPPET
          service { '#{ssh_service}': }

          googleauthenticator::pam { 'su':
            ensure => absent,
          }

          googleauthenticator::user { 'root':
            ensure     => absent,
            secret_key => 'C6SSDFBBH6P76EDM',
          }
        PUPPET
      end
    end

    describe file('/etc/pam.d/su') do
      its(:content) { is_expected.not_to match(%r{google-authenticator}) }
    end

    describe file('/etc/pam.d/login') do
      its(:content) { is_expected.to match(%r{^#{pam_include}google-authenticator-root-only$}) }
    end

    describe file('/root/.google_authenticator') do
      it { is_expected.not_to exist }
    end
  end
end
