module Jekyll
  class IncludeFileTag < Liquid::Tag
    def initialize(tag_name, path, tokens)
      super
      @path = path.strip
    end

    def render(context)
      file = File.join(context.registers[:site].source, @path)
      if File.exist?(file)
        File.read(file)
      else
        "ERROR: File not found: #{@path}"
      end
    end
  end
end

Liquid::Template.register_tag('include_file', Jekyll::IncludeFileTag)
