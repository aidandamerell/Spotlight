# frozen_string_literal: true

# Main Functions for all objects
# #Hashdump

def hashdump(options)
  secrets_dump = TTY::Which.which('secretsdump.py')
  catch :noprivs do
    opts = options[:opts]
    case options[:type]
    when :single
      puts "Dumping hash for user #{options[:user].name}".green
      cmd = TTY::Command.new(output: '', printer: :quiet)
      connection = cmd.run("#{secrets_dump} \'#{opts[:domain]}/#{opts[:username]}\:#{opts[:password]}\'\@#{opts[:host]} -just-dc-ntlm -just-dc-user \"#{options[:user].name}\"")
      LDAPData::User.add_hash(connection.out.split("\n")[4]) if connection.out =~ /:::$/
      puts connection.out
    when :full
      puts 'Dumping hashes for all found users'.green
      cmd = TTY::Command.new(output: '', printer: :quiet)
      connection = cmd.run("#{secrets_dump} \'#{opts[:domain]}/#{opts[:username]}\:#{opts[:password]}\'\@#{opts[:host]} -just-dc-ntlm")
      connection.each do |line|
        if line.include? ':::'
          LDAPData::User.add_hash(line)
        elsif line.include? 'ERROR_DS_DRA_ACCESS_DENIED'
          puts 'Not enough privilege, aborting hashdump'.red
          throw :noprivs
        end
      end
    end
  end
end

# Takes an object and outputs it in a pretty way
def output(object)
  object.instance_variables.each do |attribute|
    print attribute.to_s.gsub('@', '').gsub('_', ' ').capitalize.ljust(25)
    print ': '
    case value = object.instance_variable_get(attribute)
    when Array
      puts value.join(', ')
    when String
      puts value
    when Integer
      puts value
    when nil
      puts 'NIL'
    when true
      puts 'TRUE'
    else
      puts ''
    end
  end
  puts ''
end

# Create and edit a sheet
def swrite(wb_object, worksheet, headers, objects, attributes)
  # workbook is the object, worksheet will be the name of the new sheet, array will be the header row, objects will be the array of objects
  # attributes in an array of attributes - this is to control layout
  wb_object.add_worksheet(name: worksheet) do |sheet|
    sheet.add_row headers

    objects.each do |object|
      if attributes

        sheet.add_row(attributes.map do |attribute|
          if object.instance_variable_get(attribute).is_a? Array
            object.instance_variable_get(attribute).map do |i|
              i.respond_to?(:pretty_id) ? i.pretty_id : i.name
            rescue StandardError
              i
            end.compact.join(', ')
          else
            object.instance_variable_get(attribute)
          end
        end)
      else
        sheet.add_row(object.instance_variables.map do |attribute|
          if object.instance_variable_get(attribute).is_a? Array
            object.instance_variable_get(attribute).map do |i|
              i.name
            rescue StandardError
              i
            end.join(', ')
          else
            object.instance_variable_get(attribute)
          end
        end)
      end
    end
  end
end

def password_policy_output(wb_object, data)
  wb_object.add_worksheet(name: 'Password Policy') do |sheet|
    sheet.add_row %w[Setting Value]
    sheet.add_row ['Domain Name', data.name]
    sheet.add_row ['Max Password Age', data.maxpwdage]
    sheet.add_row ['Min Password Age', data.minpwdage]
    sheet.add_row ['Lockout Window', data.lockoutobservationwindow]
    sheet.add_row ['Lockout Duration', data.lockoutduration]
    sheet.add_row ['Lockout Threshold', data.lockoutthreshold]
    sheet.add_row ['Min Password Length', data.minpwdlength]
    sheet.add_row ['Password Properties', data.pwdproperties]
    sheet.add_row ['Password History', data.pwdhistorylength]
  end
end

def get_sid_string(data)
  return if data.nil?

  sid = []
  sid << data[0].to_s
  rid = ''
  6.downto(1) do |i|
    rid += byte2hex(data[i, 1][0])
  end
  sid << rid.to_i.to_s
  sid += data.unpack('bbbbbbbbV*')[8..]
  sid[-1]
rescue StandardError
  nil
end

def byte2hex(b)
  ret = format('%x', (b.to_i & 0xff))
  ret = "0#{ret}" if ret.length < 2
  ret
end

def shutdown
  puts 'Exiting...'.red
  exit
end
