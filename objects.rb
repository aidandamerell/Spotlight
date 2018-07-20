module LDAPData

	
	#This method is designed to take an BER object and convert it to something normal
	def self.breakout(object)
		if object.is_a? Array
			if object.size == 1
				if object[0].is_a? String
					if object[0] =~ /^-?[0-9]{0,20}$/ #If the value is an integer
						return object[0].to_i
					else
						return object[0].to_s
					end
				end

			elsif object.size >= 1
				instance = []
				object.to_a.each do |item|
					if item.is_a? String
						instance << item.to_s
					end
				end
				return instance
			end
		elsif object.is_a? String
			if object.to_i =~ /^-?[0-9]{0,20}$/
				return object.to_i
			else
				return object.to_s
			end
		end
	end

	#Take an LDAP entry and turn it into a hash
	def self.entry_to_hash(entry)
		entry_hash = {}
		entry.each do |k, v|
			entry_hash[k] = LDAPData.breakout(v)
		end
		return entry_hash
	end


	#LDAP Data manipulation

	def self.windows_time(date)
		begin
			windowsTime = date.to_i || 128976739610612366 #default value
			unixTime = windowsTime/10000000-11644473600
			date = Time.at(unixTime) #stupid date time
			if [30828 ,1600, 1601].include?(date.year)
				return "Never"
			else
				return date.to_date.strftime
			end
		rescue
			return "Error"
		end
	end

	def self.windows_time_two(date)
		begin
			date = Date.strptime(date,"%Y%m%d%H%M%S")
			if [30828 ,1600, 1602].include?(date.year)
				return "Never"
			else
				return date.strftime
			end
		rescue
			return "Error"
		end
	end

	#LDAP Filters
	##user
	def self.find_one_user(username)
		Net::LDAP::Filter.construct("(&(SAMAccountName=#{Net::LDAP::Filter.escape(username)}))")
	end

	def self.recursive_user_memberof(dn)
		Net::LDAP::Filter.construct("(member:1.2.840.113556.1.4.1941:=#{Net::LDAP::Filter.escape(dn)})")
	end

	def self.find_all_users
		Net::LDAP::Filter.construct("(objectCategory=Person)")
	end

	##group

	def self.find_one_group(groupname)
		Net::LDAP::Filter.construct("(&(objectCategory=Group)(sAMAccountName=#{groupname}))")
	end

	def self.recursive_group_memberof(dn)
		#take a group DN and find all the nested users in the group
		Net::LDAP::Filter.construct("(&(objectCategory=Person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:=#{Net::LDAP::Filter.escape(dn)}))")
	end

	def self.find_all_groups
		Net::LDAP::Filter.construct("(|(objectCategory=Group)(objectCategory=OU))")
	end

	##domain
	def self.find_domain_trusts
		Net::LDAP::Filter.construct("(objectCategory=trusteddomain)")
	end

	def self.current_domain_info
		Net::LDAP::Filter.construct("(objectCategory=domain)")
	end

	##computer
	def self.find_computer(type)
		case type
			when "domaincontrollers"			
				return domain_controller = Net::LDAP::Filter.construct("(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))")
			when "servers"
				return Net::LDAP::Filter.construct("(&(&(objectCategory=computer)(operatingSystem=Windows Server*)))")
			when "all"
				return  Net::LDAP::Filter.construct("(&(&(objectCategory=computer)))")
			when "workstations"
				compfilter = Net::LDAP::Filter.eq("Objectcategory", "Computer")
				notfilter = ~ Net::LDAP::Filter.eq( "operatingSystem", "Windows Server*" )
				return filter = Net::LDAP::Filter.join(compfilter, notfilter)
			end
	end

	def self.dn_to_human(cn)
		#where cn is a string or array of strings, take the first CN=
		if cn.is_a? String
			return cn.split(",")[0].gsub("CN=","")
		elsif cn.is_a? Array
			array = []
			cn.each do |string|
				array << string.split(",")[0].gsub("CN=","")
			end
			return array
		end
	end


	#Objects we create from LDAP objects
	class Forest #I dont see a reason to have this yet
	end

	class Domain
		attr_accessor :flatname, :name, :trustdirection, :trusttype, :dn, :trustattributes, :lockoutduration, :cn, :current, :base,
		:lockoutobservationwindow, :lockoutthreshold, :maxpwdage, :minpwdage, :minpwdlength, :pwdproperties, :pwdhistorylength, :fqdn

		@@domains = Array.new
		def initialize(options ={})
			@name = options[:name] || options[:cn]
			@flatname = options[:flatname] || options[:name]
			@dn = options[:dn]
			@cn = options[:cn]
			if options[:current] #If this is the current domain we can grab the password information
				@lockoutobservationwindow = (options[:lockoutobservationwindow].abs / 600000000)
				@lockoutduration = (options[:lockoutduration].abs / 600000000)
				@lockoutthreshold = options[:lockoutthreshold]
				@maxpwdage =  (options[:maxpwdage].abs / 864000000000) #days and days
				@minpwdage = (options[:minpwdage].abs / 864000000000) #days and days
				@minpwdlength = options[:minpwdlength]
				@pwdproperties = self.domain_pwd_properties(options[:pwdproperties])
				@pwdhistorylength = options[:pwdhistorylength]
				@fqdn = @dn.gsub(",DC=",".").sub("DC=","")
				@current = self
			else
				@fqdn = @cn
				@trustdirection = self.domain_trust_direction(options[:trustdirection])
				@trusttype = self.domain_trust_type(options[:trusttype])
				@trustattributes = domain_trust_attributes(options[:trustattributes])
			end
			@@domains << self
		end

		def self.current
			self.all_domains.find {|i| i.current }
		end

		def domain_trust_direction(direction)
			case direction
				when 1
					"Inbound"
				when 2
					"Outbound"
				when 3
					"Bidirectional"
				when "default"
					"NA"
			end
		end

		def domain_trust_type(type)
			case type
				when 1
					"Windows NT"
				when 2
					"Active Directory"
				when 3
					"Kerberos Realm"
				when 4
					"DCE"
				when "default"
					"N/A"
			end
		end

		def domain_trust_attributes(attributes) #This make not work as self might not be what case is, objects ey
			if attributes.is_a? Array
			 e = attributes.map {|i| i.to_i}
			else
				e = [attributes]
			end
				if e.include? 1
					"Not transitive"
				elsif e.include? 2
					"Only 2000 & Above can use this trust"
				elsif e.include? 4
					"SID Filtering Enabled"
				elsif e.include? 8
					"Forest Trust"
				elsif e.include? 16
					"Cross-org” trust with selective authentication enabled"
				elsif e.include? 32
					"Forest-internal"
				elsif e.include? 64
					"This is a forest trust with SIDHistory enabled"
			end
		end

		def domain_pwd_properties(attributes)
			case attributes
				when 1
					"DOMAIN PASSWORD COMPLEX"
				when 2
					"DOMAIN PASSWORD NO ANON CHANGE"
				when 8
					"DOMAIN LOCKOUT ADMINS"
				when 16
					"DOMAIN PASSWORD STORE CLEARTEXT"
				when 32
					"DOMAIN REFUSE PASSWORD CHANGE"
				end
		end

		def self.all_domains
			@@domains
		end
	end


	class Group

		attr_accessor :name, :dn, :members, :administrative, :count

		@@groups = Array.new
		@@administrative_groups = [/domain admins/i,/Administrators/i,/Enterprise admins/i,/Remote Desktop Users/i,/Server Admins/i]
		@@regex = Regexp.union (@@administrative_groups)

		def initialize(options ={})
			@name = options[:samaccountname] || options[:name]
			@dn = options[:dn] || options[:distinguishedname]
			@members = [LDAPData.dn_to_human(options[:member])] || []
			@admincount = options[:admincount]
			if @name.match(@@regex) or @admincount
				@administrative = true
			else
				@administrative = nil
			end
			@count = @members.count
			@@groups << self
		end

		def self.all_groups
			@@groups
		end

		def self.administrative_groups
			@@groups.select { |group| group.administrative }
		end


	end

	class User
		attr_accessor :name, :memberof, :dn, :whencreated, :badpwdcount, :cracked, :samaccountname,
		:badpasswordtime, :admincount, :accountexpires, :hash, :hash_type, :description, :enabled, :hash_type,
		:password, :external

		@@users = Array.new
		#The user object takes a hash of values from an LDAP object
		def initialize(options ={})

			if @@users.find {|user| user.dn == options[:dn] } #We dont want duplicated in our array so lets see if the group cn already exists
				return #Have a think about this, we dont want to ignore new data if there is more than the existing object
			end

			@name = options[:name] || options[:samaccountname]
			@samaccountname = options[:samaccountname] #Name will be set on users but not service accounts
			@dn = options[:dn]
			@memberof = LDAPData.dn_to_human(options[:memberof])
			@whencreated = LDAPData.windows_time_two(options[:whencreated])
			@badpasswordtime = LDAPData.windows_time(options[:badpasswordtime])
			@accountexpires = LDAPData.windows_time(options[:accountexpires])
			@badpwdcount = options[:badpwdcount]
			@admincount = options[:admincount]
			@description = options[:description]
			@enabled = self.user_account_enabled(options[:useraccountcontrol])
			@hash = nil
			@hash_type = nil
			@cracked = nil #if the john / hashcat output contained the hash
			@external = nil 
			@password = nil
			@@users << self
			
		end

		def self.all_users
			@@users
		end

		def self.add_hash(hash)
			#Format: domain\uid:rid:lmhash:nthash
			if hash.split(":")[0].include? "\\"
				 username = hash.split(":")[0].split("\\")[1]
			else
				username = hash.split(":")[0]
			end
			user = @@users.find { |user| user.samaccountname == username }
			unless user.nil?
				user.hash = hash
				user.hash_type = self.password_hash_type(hash)
			end
		end

		def self.password_hash_type(hash)
			if hash.nil?
				"EMPTY"
			elsif hash.include? '31d6cfe0d16ae931b73c59d7e0c089c0'
				"BLANK"
			elsif hash.include? 'aad3b435b51404eeaad3b435b51404ee'
				"NTLM"
			else
				"LM"
			end
		end

		def user_account_enabled(value)
		#useraccountcontrol
			if [512, 66048].include? value
				true
			else
				false
			end
		end

		def self.cracked(file)
			file.readlines.each do |line|
				if user = @@users.find {|user| user.samaccountname == line.split(":")[0] }
					user.cracked = true
					user.password = line.split(":")[1]
					if user.hash.nil?
						user.hash = line
					end
				end
			end	
		end

		def self.redact
			@@users.each do |user|
				user.hash = "REDACTED"
				if user.hash_type == "BLANK"
					user.password = "BLANK"
				elsif user.password
					user.password = "Cracked"
				else
					user.password = "Not Cracked"
				end
			end
		end

		def self.external(file)
			file.readlines.each do |line|
				if user = @@users.find {|user| user.name == line.chomp }
					user.external = true
				end
			end
		end
		
	end

	class Computer

		attr_accessor :name, :dn, :dns, :os, :os_sp, :ip
		
		@@computers = Array.new

		def initialize(options ={})

			@name = options[:name] || options[:cn]
			@dn = options[:dn]
			@os = options[:operatingsystem]
			@os_sp = options[:operatingsystemservicepack]
			@dns = options[:dnshostname]
			@ip = nil
			@@computers << self
		end

		def self.all_computers
			@@computers
		end

		def self.resolver(resolver, name)
			return (resolver.getaddress "#{name}").to_s
		rescue Resolv::ResolvError
			return "Unable to Resolve"
		end
	end
end