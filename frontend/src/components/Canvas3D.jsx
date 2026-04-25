import { useEffect, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Float, Icosahedron, MeshDistortMaterial, OrbitControls, Sphere, Torus } from '@react-three/drei';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

function SceneCluster({ variant, active, scrollTarget }) {
  const clusterRef = useRef(null);
  const coreRef = useRef(null);
  const ringRef = useRef(null);
  const beaconRef = useRef(null);
  const { camera } = useThree();

  useEffect(() => {
    if (variant !== 'webgl' || !active || !clusterRef.current) {
      return undefined;
    }

    const timeline = gsap.timeline({
      defaults: { ease: 'none' },
      scrollTrigger: {
        trigger: scrollTarget,
        start: 'top top',
        end: 'bottom bottom',
        scrub: 0.9,
      },
    });

    timeline
      .to(clusterRef.current.rotation, { x: 1.05, y: 2.75, z: 0.42 }, 0)
      .to(clusterRef.current.position, { y: -0.4, z: -0.38 }, 0)
      .to(camera.position, { z: 3.12, y: 0.16 }, 0)
      .to(camera.rotation, { x: -0.06 }, 0);

    return () => {
      timeline.scrollTrigger?.kill();
      timeline.kill();
    };
  }, [active, camera, scrollTarget, variant]);

  useFrame((state, delta) => {
    if (!clusterRef.current || !coreRef.current || !ringRef.current || !beaconRef.current) {
      return;
    }

    const time = state.clock.getElapsedTime();
    const driftFactor = variant === 'webgl' ? 1 : 0.6;

    clusterRef.current.rotation.y += delta * 0.12 * driftFactor;
    coreRef.current.rotation.x += delta * 0.19;
    ringRef.current.rotation.z += delta * 0.33;
    beaconRef.current.position.y = Math.sin(time * 1.2) * 0.34;
  });

  return (
    <group ref={clusterRef}>
      <Float
        speed={variant === 'webgl' ? 1.35 : 0.8}
        rotationIntensity={variant === 'webgl' ? 1.45 : 0.7}
        floatIntensity={variant === 'webgl' ? 0.88 : 0.42}
      >
        <Icosahedron ref={coreRef} args={[1.02, 1]}>
          <MeshDistortMaterial
            color={variant === 'webgl' ? '#9deaff' : '#5ccfff'}
            emissive={variant === 'webgl' ? '#2ca5d9' : '#166895'}
            emissiveIntensity={variant === 'webgl' ? 0.48 : 0.24}
            distort={variant === 'webgl' ? 0.34 : 0.25}
            speed={variant === 'webgl' ? 2.5 : 1.4}
            roughness={0.18}
            metalness={0.74}
            clearcoat={1}
            clearcoatRoughness={0.08}
          />
        </Icosahedron>
      </Float>

      <Torus ref={ringRef} args={[1.58, 0.08, 24, 160]} rotation={[1.15, 0.18, 0.05]}>
        <meshStandardMaterial
          color="#ffd58a"
          emissive="#d59a38"
          emissiveIntensity={0.34}
          roughness={0.25}
          metalness={0.82}
        />
      </Torus>

      <Sphere ref={beaconRef} args={[0.17, 32, 32]} position={[1.72, 0.12, 0.28]}>
        <meshStandardMaterial
          color="#89e6ff"
          emissive="#48c3f1"
          emissiveIntensity={0.76}
          roughness={0.14}
          metalness={0.45}
        />
      </Sphere>

      <Sphere args={[0.1, 20, 20]} position={[-1.48, -0.44, -0.42]}>
        <meshStandardMaterial
          color="#b8edff"
          emissive="#6dbfdd"
          emissiveIntensity={0.45}
          roughness={0.22}
          metalness={0.56}
        />
      </Sphere>
    </group>
  );
}

export default function Canvas3D({
  variant = 'ambient',
  className = '',
  active = true,
  scrollTarget = '.at-home',
}) {
  const cameraZ = variant === 'webgl' ? 3.85 : 4.4;
  const cameraFov = variant === 'webgl' ? 46 : 52;

  return (
    <div className={className} aria-hidden="true">
      <Canvas
        camera={{ position: [0, 0, cameraZ], fov: cameraFov }}
        dpr={[1, 1.8]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={variant === 'webgl' ? 0.38 : 0.28} />
        <directionalLight
          position={[3.2, 4.1, 3.4]}
          intensity={variant === 'webgl' ? 1.18 : 0.9}
          color="#8ad7ff"
        />
        <pointLight
          position={[-4.2, -2.3, -2.6]}
          intensity={variant === 'webgl' ? 1.24 : 0.78}
          color="#ffc477"
        />

        <SceneCluster variant={variant} active={active} scrollTarget={scrollTarget} />

        {variant === 'ambient' && (
          <OrbitControls
            enableZoom={false}
            enablePan={false}
            enableRotate={false}
            autoRotate
            autoRotateSpeed={0.45}
          />
        )}
      </Canvas>
    </div>
  );
}
