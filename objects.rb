# frozen_string_literal: true

class UAC
  class << self
    attr_accessor :values

    def load
      self.values = YAML.load_file('uac_values.yml') || {}
    rescue StandardError
      puts 'Error loading UAC values, values will be ignored'.red
    end
  end
end

module LDAPData
  def self.load_from_restore(data)
    YAML.unsafe_load_file(data).each do |object|
      case object
      when LDAPData::User
        LDAPData::User.all_users << object
      when LDAPData::Group
        LDAPData::Group.all_groups << object
      when LDAPData::Computer
        LDAPData::Computer.all_computers << object
      when LDAPData::Domain
        LDAPData::Domain.all_domains << object
      end
    end
  end

  # This method is designed to take an BER object and convert it to something normal
  def self.breakout(object)
    if object.is_a? Array
      if object.size == 1
        if object[0].is_a? String
          if object[0] =~ /^-?[0-9]{0,20}$/ # If the value is an integer
            object[0].to_i
          else
            object[0].to_s
          end
        end

      elsif object.size >= 1
        instance = []
        object.to_a.each do |item|
          instance << item.to_s if item.is_a? String
        end
        instance
      end
    elsif object.is_a? String
      if object.to_i =~ /^-?[0-9]{0,20}$/
        object.to_i
      else
        object.to_s
      end
    end
  end

  # Take an LDAP entry and turn it into a hash
  def self.entry_to_hash(entry)
    entry_hash = {}
    entry.each do |k, v|
      entry_hash[k] = LDAPData.breakout(v)
    end
    entry_hash
  end

  # LDAP Data manipulation

  def self.windows_time(date)
    windowsTime = date.to_i || 128_976_739_610_612_366 # default value
    unixTime = windowsTime / 10_000_000 - 11_644_473_600
    date = Time.at(unixTime) # stupid date time
    if [30_828, 1600, 1601].include?(date.year)
      'Never'
    else
      date.to_date.strftime
    end
  rescue StandardError
    'Error'
  end

  def self.windows_time_two(date)
    date = Date.strptime(date, '%Y%m%d%H%M%S')
    if [30_828, 1600, 1602].include?(date.year)
      'Never'
    else
      date.strftime
    end
  rescue StandardError
    'Error'
  end

  # LDAP Filters
  # #user
  def self.find_one_user(username)
    Net::LDAP::Filter.construct("(&(SAMAccountName=#{Net::LDAP::Filter.escape(username)}))")
  end

  def self.recursive_user_memberof(dn)
    Net::LDAP::Filter.construct("(member:1.2.840.113556.1.4.1941:=#{Net::LDAP::Filter.escape(dn)})")
  end

  def self.find_all_users
    Net::LDAP::Filter.construct('(objectCategory=Person)')
  end

  # #group

  def self.find_one_group(groupname)
    Net::LDAP::Filter.construct("(&(objectCategory=Group)(sAMAccountName=#{groupname}))")
  end

  def self.recursive_group_memberof(dn)
    # take a group DN and find all the nested users in the group
    Net::LDAP::Filter.construct("(&(objectCategory=Person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:=#{Net::LDAP::Filter.escape(dn)}))")
  end

  def self.find_all_groups
    Net::LDAP::Filter.construct('(|(objectCategory=Group)(objectCategory=OU))')
  end

  # #domain
  def self.find_domain_trusts
    Net::LDAP::Filter.construct('(objectCategory=trusteddomain)')
  end

  def self.current_domain_info
    Net::LDAP::Filter.construct('(objectCategory=domain)')
  end

  # #computer
  def self.find_computer(type)
    case type
    when 'domaincontrollers'
      Net::LDAP::Filter.construct('(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))')
    when 'servers'
      Net::LDAP::Filter.construct('(&(&(objectCategory=computer)(operatingSystem=Windows Server*)))')
    when 'all'
      Net::LDAP::Filter.construct('(&(&(objectCategory=computer)))')
    when 'workstations'
      compfilter = Net::LDAP::Filter.eq('Objectcategory', 'Computer')
      notfilter = ~ Net::LDAP::Filter.eq('operatingSystem', 'Windows Server*')
      Net::LDAP::Filter.join(compfilter, notfilter)
    end
  end

  def self.dn_to_human(cn)
    # where cn is a string or array of strings, take the first CN=
    if cn.is_a? String
      cn.split(',CN=')[0].gsub('CN=', '')
    elsif cn.is_a? Array
      array = []
      cn.each do |string|
        array << string.split(',CN=')[0].gsub('CN=', '')
      end
      array
    end
  end

  # Objects we create from LDAP objects
  # I dont see a reason to have this yet
  class Forest
  end

  class Domain
    attr_accessor :flatname, :name, :trustdirection, :trusttype, :dn, :trustattributes, :lockoutduration, :cn, :current, :base,
                  :lockoutobservationwindow, :lockoutthreshold, :maxpwdage, :minpwdage, :minpwdlength, :pwdproperties, :pwdhistorylength, :fqdn

    @@domains = []
    def initialize(options = {})
      @name = options[:name] || options[:cn]
      @flatname = options[:flatname] || options[:name]
      @dn = options[:dn]
      @cn = options[:cn]
      if options[:current] # If this is the current domain we can grab the password information
        @current                  = self
        @fqdn                     = @dn.gsub(',DC=', '.').sub('DC=', '')
        @lockoutobservationwindow = extract_time(options[:lockoutobservationwindow], 600_000_000)
        @lockoutduration          = extract_time(options[:lockoutduration], 600_000_000)
        @lockoutthreshold         = options[:lockoutthreshold]
        @maxpwdage                = extract_time(options[:maxpwdage], 864_000_000_000) # days and days
        @minpwdage                = extract_time(options[:minpwdage], 864_000_000_000) # days and days
        @minpwdlength             = options[:minpwdlength]
        @pwdproperties            = domain_pwd_properties(options[:pwdproperties])
        @pwdhistorylength         = options[:pwdhistorylength]
      else
        @fqdn = @cn
        @trustdirection = domain_trust_direction(options[:trustdirection])
        @trusttype = domain_trust_type(options[:trusttype])
        @trustattributes = domain_trust_attributes(options[:trustattributes])
      end
      @@domains << self
    end

    def self.current
      all_domains.find(&:current)
    end

    def domain_trust_direction(direction)
      case direction
      when 1
        'Inbound'
      when 2
        'Outbound'
      when 3
        'Bidirectional'
      when 'default'
        'NA'
      end
    end

    def domain_trust_type(type)
      case type
      when 1
        'Windows NT'
      when 2
        'Active Directory'
      when 3
        'Kerberos Realm'
      when 4
        'DCE'
      when 'default'
        'N/A'
      end
    end

    # This make not work as self might not be what case is, objects ey
    def domain_trust_attributes(attributes)
      e = if attributes.is_a? Array
            attributes.map(&:to_i)
          else
            [attributes]
          end
      if e.include? 1
        'Not transitive'
      elsif e.include? 2
        'Only 2000 & Above can use this trust'
      elsif e.include? 4
        'SID Filtering Enabled'
      elsif e.include? 8
        'Forest Trust'
      elsif e.include? 16
        'Cross-org” trust with selective authentication enabled'
      elsif e.include? 32
        'Forest-internal'
      elsif e.include? 64
        'This is a forest trust with SIDHistory enabled'
      end
    end

    def domain_pwd_properties(attributes)
      case attributes
      when 1
        'DOMAIN PASSWORD COMPLEX'
      when 2
        'DOMAIN PASSWORD NO ANON CHANGE'
      when 8
        'DOMAIN LOCKOUT ADMINS'
      when 16
        'DOMAIN PASSWORD STORE CLEARTEXT'
      when 32
        'DOMAIN REFUSE PASSWORD CHANGE'
      end
    end

    def self.all_domains
      @@domains
    end

    private

    def extract_time(attribute, divider)
      return 0 unless attribute

      attribute.abs / divider
    rescue StandardError
      0
    end
  end

  class Group
    attr_accessor :name, :dn, :members, :administrative, :count

    @@groups = []
    @@administrative_groups = [/domain admins/i, /Administrators/i, /Enterprise admins/i, /Remote Desktop Users/i,
                               /Server Admins/i]
    @@regex = Regexp.union(@@administrative_groups)

    def initialize(options = {})
      @name = options[:samaccountname] || options[:name]
      @dn = options[:dn] || options[:distinguishedname]
      @admincount = options[:admincount]
      @administrative = is_possibly_administrative(@name, @admincount)
      @members = add_members(options[:member])
      @count = @members.count
      @@groups << self
    end

    def is_possibly_administrative(group_name, admincount)
      string_name = group_name.to_s

      true if string_name.match(@@regex) || admincount
    rescue StandardError
      nil
    end

    def self.all_groups
      @@groups
    end

    def self.administrative_groups
      @@groups.select(&:administrative)
    end

    def self.administrative_group_members
      administrative_groups.map(&:members).flatten.uniq(&:dn)
    end

    def add_members(users)
      # Take the collector of users, search the User class for each user and return if we have that user as a "User"
      collection = []
      # binding.pry
      if users.is_a? String
        collection << User.all_users.select { |i| i.dn == users }.first
      elsif users.is_a? Array
        users.each do |user|
          # binding.pry
          if (i = User.all_users.select { |i| i.dn == user }.first)
            collection << i
          else
            a = @@groups.select { |i| i.dn == user }.first
            collection << a
          end
        end
      end
      collection
    end
  end

  class User
    attr_accessor :name, :memberof, :dn, :whencreated, :badpwdcount, :cracked, :samaccountname,
                  :badpasswordtime, :admincount, :accountexpires, :hash, :hash_type, :description, :enabled, :hash_type,
                  :password, :external, :lastlogon, :sid, :uac, :email_address, :password_last_set

    @@users = []
    # The user object takes a hash of values from an LDAP object
    def initialize(options = {})
      if @@users.find do |user|
           user.guid == options[:objectguid].unpack('H*')
      rescue StandardError
        nil
         end
        # return #Have a think about this, we dont want to ignore new data if there is more than the existing object
        return
      end

      @name            = options[:name] || options[:samaccountname]
      @samaccountname  = options[:samaccountname] # Name will be set on users but not service accounts
      @dn              = options[:dn]
      @memberof        = LDAPData.dn_to_human(options[:memberof])
      @whencreated     = LDAPData.windows_time_two(options[:whencreated])
      @badpasswordtime = LDAPData.windows_time(options[:badpasswordtime])
      @accountexpires  = LDAPData.windows_time(options[:accountexpires])
      @last_logon      = LDAPData.windows_time(options[:lastlogon])
      @badpwdcount     = options[:badpwdcount]
      @admincount      = options[:admincount]
      @description     = options[:description]
      @enabled         = user_account_enabled(options[:useraccountcontrol])
      @sid             = get_sid_string(options[:objectsid])
      @uac             = user_account_control(options[:useraccountcontrol]) || options[:useraccountcontrol]
      @guid            = begin
        options[:objectguid]&.unpack 'H*'
      rescue StandardError
        nil
      end
      @hash            = nil
      @hash_type       = nil
      @cracked         = nil # if the john / hashcat output contained the hash
      @external        = nil
      @password        = nil
      @email_address   = options[:mail] || get_email_from_proxy_address(options[:proxyaddresses])
      @password_last_set = LDAPData.windows_time(options[:pwdlastset])
      @@users << self
    end

    def self.all_users
      @@users
    end

    def pretty_id
      samaccountname
    end

    def self.enabled_users
      all_users.select(&:enabled)
    end

    def self.add_hash(hash)
      # Format: domain\uid:rid:lmhash:nthash
      username = if hash.split(':')[0].include? '\\'
                   hash.split(':')[0].split('\\')[1]
                 else
                   hash.split(':')[0]
                 end
      user = @@users.find { |user| user.samaccountname == username }
      return if user.nil?

      user.hash = hash
      user.hash_type = password_hash_type(hash)
    end

    def self.password_hash_type(hash)
      if hash.nil?
        'EMPTY'
      elsif hash.include? '31d6cfe0d16ae931b73c59d7e0c089c0'
        'BLANK'
      elsif hash.include? 'aad3b435b51404eeaad3b435b51404ee'
        'NTLM'
      else
        'LM'
      end
    end

    def get_email_from_proxy_address(array)
      return nil unless array && !array.empty?

      string = array.find { |i| i.include? 'smtp:' }

      string[5..]
    rescue StandardError
      ''
    end

    def user_account_enabled(value)
      # useraccountcontrol
      if [512, 66_048, 4_194_816].include? value
        true
      else
        false
      end
    end

    def user_account_control(value)
      UAC.values[value]
    end

    def self.cracked(file)
      count = 0
      found_count = 0
      admin_found_count = 0
      file.readlines.each do |line|
        count += 1
        # determine if we need to remove the domain from the line
        cracked_username = line.split(':')[0]
        cracked_username = cracked_username.split('\\')[1] if cracked_username.include?('\\')

        if (user = all_users.find { |user| user.samaccountname == cracked_username })
          found_count += 1
          user.cracked = true
          user.password = line.split(':')[-1]
          user.hash = line if user.hash.nil?

          # Lastly, report is the user is in an ~admin group
          admin_esque = false
          admin_groups = []
          Group.administrative_groups.each do |admin_group|
            if user.enabled && admin_group.members.include?(user)
              admin_esque = true
              admin_groups << admin_group.name
            end
          end

          if admin_esque
            puts "Admin User Cracked and Enabled: #{user.samaccountname}:#{user.password.chomp} (Group: #{admin_groups.join(', ')})".green
            admin_found_count += 1
          end
        else
          puts "Not Found: #{line}".red unless line.chomp.empty?
        end
      end

      puts 'Basic Statistics'.blue
      puts "Total Mapped to User Count: #{found_count}".blue
      puts "Total Hashes in Dump: #{count}".blue
      puts "Enabled & Cracked Percent: #{((found_count.to_f / enabled_users.count) * 100).ceil(2)}%".blue
      puts "Admin-esque Cracked Percent: #{((admin_found_count.to_f / Group.administrative_group_members.count) * 100).ceil(2)}%".blue
    end

    def self.redact
      all_users.each do |user|
        user.hash = 'REDACTED'
        user.password = if user.password
                          'Cracked'
                        else
                          'Not Cracked'
                        end
      end
    end

    def self.external(file, attribute)
      attribute ||= 'email_address'
      count = 0
      file.readlines.each do |line|
        if (user = @@users.find { |user| user.send(attribute.to_sym)&.downcase == line.chomp })
          count += 1
          user.external = true
        end
      end
      puts "#{count}\n".green
    end
  end

  class Computer
    attr_accessor :name, :dn, :dns, :os, :os_sp, :ip, :laps, :last_logon

    @@computers = []

    def initialize(options = {})
      @name  = options[:name] || options[:cn]
      @dn    = options[:dn]
      @os    = options[:operatingsystem]
      @os_sp = options[:operatingsystemservicepack]
      @dns   = options[:dnshostname]
      @laps  = options[:"ms-mcs-admpwd"]
      @last_logon = LDAPData.windows_time(options[:lastlogon])
      @ip = nil
      @@computers << self
    end

    def self.all_computers
      @@computers
    end

    def self.resolver(resolver, name)
      (resolver.getaddress name.to_s).to_s
    rescue Resolv::ResolvError
      'Resolution Error'
    end
  end
end
