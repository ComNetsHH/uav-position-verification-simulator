import math, random

class Position(object):
    def __init__(self, env, initial_position, x_min, x_max, y_min, y_max, v_max = 33):
        self.env = env
        self.last_pos = initial_position
        self.last_ts = env.now

        self.x_min = x_min
        self.x_max = x_max
        self.y_min = y_min
        self.y_max = y_max

        self.v_max = v_max

        self.angle = random.uniform(0, 2 * math.pi)  # Initial random direction
        self.speed = random.uniform(1, v_max)  # Initial random speed

        self.env.process(self.run())


    def get_position(self):
        elapsed_time = self.env.now - self.last_ts
        x = self.last_pos[0] + self.speed * elapsed_time * math.cos(self.angle)
        y = self.last_pos[1] + self.speed * elapsed_time * math.sin(self.angle)
        return (x, y)

    def update_position(self):
        pos = self.get_position()
        self.last_pos = pos
        self.last_ts = self.env.now
        self.angle = random.uniform(0, 2 * math.pi)  # Initial random direction
        self.speed = random.uniform(1, self.v_max)  # Initial random speed

    def run(self):
        while True:
            speed_x = self.speed * math.cos(self.angle)
            speed_y = self.speed * math.sin(self.angle)

            pos = self.get_position()

            dist_x = self.x_min - pos[0] if speed_x < 0 else self.x_max - pos[0]
            dist_y = self.y_min - pos[1] if speed_y < 0 else self.y_max - pos[1]

            t_x = dist_x / speed_x
            t_y = dist_y / speed_y

            t = max(0, min(t_x, t_y))

            yield self.env.timeout(t)
            self.update_position()



