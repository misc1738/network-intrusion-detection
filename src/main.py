from detector import NetworkDetector
from model import IntrusionDetectionModel

def main():
    # 初始化模型
    model = IntrusionDetectionModel(timesteps=10, features=5)
    
    # 初始化检测器
    detector = NetworkDetector(model)
    
    # 启动检测
    detector.start_detection()

if __name__ == "__main__":
    main()