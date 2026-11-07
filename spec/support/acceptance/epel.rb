# frozen_string_literal: true

# google-authenticator is shipped in EPEL on EL
RSpec.configure do |c|
  c.before :suite do
    hosts.each do |host|
      next unless fact_on(host, 'os.family') == 'RedHat'

      epel = if fact_on(host, 'os.name') == 'OracleLinux'
               "oracle-epel-release-el#{fact_on(host, 'os.release.major')}"
             else
               'epel-release'
             end
      host.install_package(epel)
    end
  end
end
