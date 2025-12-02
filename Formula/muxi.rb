class Muxi < Formula
	desc "Local TLS reverse proxy for mapping hostnames to localhost ports"
	homepage "https://github.com/shff/muxi"
	url "https://github.com/shff/muxi.git", using: :git, branch: "main"
	version "0.0.1"
	license "MIT"

	depends_on "go" => :build

	def install
		system "go", "build", *std_go_args(ldflags: "-s -w")
	end

	service do
		run [opt_bin/"muxi", "--daemon"]
		keep_alive true
		working_dir var
		log_path var/"log/muxi.log"
		error_log_path var/"log/muxi.log"
	end

	test do
		# `-list` should exit successfully even with an empty config directory
		output = shell_output("#{bin}/muxi -list")
		assert_equal "", output.strip
	end
end
