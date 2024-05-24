class RandomUtil:
	@staticmethod
	def generate_random_string(length=32):
		rnd_str = ''.join(random.choice(['I', 'l']) for _ in range(length))
		return rnd_str