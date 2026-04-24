import { useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function EncryptionScene({ variant = 'login', isUnlocking = false, isLocking = false }) {
  const mountRef = useRef(null);
  
  // Track unlock state
  const isUnlockingRef = useRef(isUnlocking);
  const unlockProgress = useRef(0);

  // Track lock state
  const isLockingRef = useRef(isLocking);
  const lockProgress = useRef(0);

  useEffect(() => {
    isUnlockingRef.current = isUnlocking;
    isLockingRef.current = isLocking;
  }, [isUnlocking, isLocking]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const W = mount.clientWidth;
    const H = mount.clientHeight;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0); 
    mount.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, W / H, 0.1, 100);
    camera.position.set(0, 0, 6); 

    // ── LIGHTS ──────────────────────────────────────────────────────────────
    const ambientLight = new THREE.AmbientLight(0x0a0a1a, 2);
    scene.add(ambientLight);

    const cyanLight = new THREE.PointLight(0x00e5ff, 6, 15);
    cyanLight.position.set(2, 2, 3);
    scene.add(cyanLight);

    const purpleLight = new THREE.PointLight(0x7c3aed, 4, 12);
    purpleLight.position.set(-2, -1, 2);
    scene.add(purpleLight);

    const rimLight = new THREE.PointLight(0x00ff88, 2, 10);
    rimLight.position.set(0, -3, -2);
    scene.add(rimLight);

    const frontFill = new THREE.DirectionalLight(0xaad8ff, 2.5);
    frontFill.position.set(0, 1, 5);
    scene.add(frontFill);


    // ── 1. ROTATING PADLOCK (Central Hero) ──────────────────────────────────
    const lockGroup = new THREE.Group();

    const bodyW = 1.6;
    const bodyH = 1.6;
    const bodyD = 0.6;
    const bodyGeo = new THREE.BoxGeometry(bodyW, bodyH, bodyD, 4, 4, 4);
    const bodyMat = new THREE.MeshStandardMaterial({
      color: 0x0f1f38, 
      metalness: 0.7,
      roughness: 0.15,
      emissive: 0x040a15,
      emissiveIntensity: 0.5
    });
    const body = new THREE.Mesh(bodyGeo, bodyMat);
    body.position.y = -0.5;
    lockGroup.add(body);

    const holeGeo = new THREE.CylinderGeometry(0.25, 0.25, 0.65, 32);
    const holeMat = new THREE.MeshStandardMaterial({ color: 0x020508, metalness: 1.0, roughness: 0.5 });
    const hole = new THREE.Mesh(holeGeo, holeMat);
    hole.position.set(0, -0.3, 0.0);
    hole.rotation.x = Math.PI / 2;
    lockGroup.add(hole);

    const coreGeo = new THREE.CylinderGeometry(0.12, 0.12, 0.68, 32);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x00ffff, emissive: 0x00e5ff, emissiveIntensity: 3.5, 
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    core.position.set(0, -0.3, 0.0);
    core.rotation.x = Math.PI / 2;
    lockGroup.add(core);
    
    const coreSlit = new THREE.Mesh(new THREE.BoxGeometry(0.06, 0.4, 0.68), coreMat);
    coreSlit.position.set(0, -0.5, 0.0);
    lockGroup.add(coreSlit);

    const shackleRadius = 0.55;
    const shackleTube = 0.15;
    const shackleMat = new THREE.MeshStandardMaterial({
      color: 0x00e5ff, emissive: 0x0088cc, emissiveIntensity: 1.5, metalness: 0.8, roughness: 0.1,
    });

    // ── Pre-calculated Hinged Shackle Group ──
    const shackle = new THREE.Group();
    const shackleBaseY = body.position.y + (bodyH / 2);
    // Anchor Group exactly at the left leg (the hinge pivot)
    shackle.position.set(-shackleRadius, shackleBaseY, 0);

    // Arch (Half circle)
    const archGeo = new THREE.TorusGeometry(shackleRadius, shackleTube, 32, 64, Math.PI);
    const arch = new THREE.Mesh(archGeo, shackleMat);
    // Align Torus so its left endpoint perfectly meets (0,0)
    arch.position.set(shackleRadius, 0.4, 0);
    shackle.add(arch);

    // Left leg (Deep Hinge pillar securely inside the lock body)
    // 1.6 length. Top at Y=0.4, so center at -0.4. Bottom sits at -1.2
    const legLgeo = new THREE.CylinderGeometry(shackleTube, shackleTube, 1.6, 32);
    const legL = new THREE.Mesh(legLgeo, shackleMat);
    legL.position.set(0, -0.4, 0); 
    shackle.add(legL);

    // Right leg (Short Pin that pops out)
    // 0.6 length. Top at Y=0.4, so center at 0.1. Bottom sits at -0.2
    const legRgeo = new THREE.CylinderGeometry(shackleTube, shackleTube, 0.6, 32);
    const legR = new THREE.Mesh(legRgeo, shackleMat);
    legR.position.set(shackleRadius * 2, 0.1, 0); 
    shackle.add(legR);

    lockGroup.add(shackle);

    const hexRingGeo = new THREE.RingGeometry(1.15, 1.25, 6);
    const hexRingMat = new THREE.MeshBasicMaterial({
      color: 0x7c3aed, transparent: true, opacity: 0.35, side: THREE.DoubleSide,
    });
    const hexRing = new THREE.Mesh(hexRingGeo, hexRingMat);
    hexRing.position.z = -0.55; 
    lockGroup.add(hexRing);

    const hexRing2 = new THREE.Mesh(
      new THREE.RingGeometry(1.5, 1.56, 6),
      new THREE.MeshBasicMaterial({ color: 0x00e5ff, transparent: true, opacity: 0.2, side: THREE.DoubleSide })
    );
    hexRing2.position.z = -0.56;
    lockGroup.add(hexRing2);

    scene.add(lockGroup);

    // ── 2. 3 ORBITAL RINGS ─────────────────────────────
    const rings = [];
    const ringMat = new THREE.MeshStandardMaterial({
      color: 0x7c3aed, emissive: 0x3b0d8f, emissiveIntensity: 0.8, metalness: 0.8, roughness: 0.2,
    });
    const ringConfigs = [
      { radius: 2.2, tube: 0.025, tilt: 0.3, speed: 0.012, mat: ringMat }, 
      { radius: 2.7, tube: 0.018, tilt: -0.6, speed: -0.009, mat: new THREE.MeshStandardMaterial({ color: 0x00e5ff, emissive: 0x006688, emissiveIntensity: 0.9, metalness: 0.7, roughness: 0.2 }) }, 
      { radius: 3.2, tube: 0.012, tilt: 1.1, speed: 0.006, mat: new THREE.MeshStandardMaterial({ color: 0x00ff88, emissive: 0x004422, emissiveIntensity: 0.6, metalness: 0.5, roughness: 0.4 }) }, 
    ];

    ringConfigs.forEach(cfg => {
      const geo = new THREE.TorusGeometry(cfg.radius, cfg.tube, 16, 100);
      const mesh = new THREE.Mesh(geo, cfg.mat);
      mesh.rotation.x = cfg.tilt;
      mesh.rotation.y = 1.0; 
      mesh.userData.speed = cfg.speed;
      scene.add(mesh);
      rings.push(mesh);
    });

    // ── 3. 12 OCTAHEDRON DATA NODES ──────────────────────────────────────────
    const nodes = [];
    const nodeCount = 12;
    const nodeGeo = new THREE.OctahedronGeometry(0.08, 0);
    const nodeMat = new THREE.MeshStandardMaterial({
      color: 0x00e5ff, emissive: 0x00aadd, emissiveIntensity: 1, metalness: 0.8, roughness: 0.1,
    });

    for (let i = 0; i < nodeCount; i++) {
      const node = new THREE.Mesh(nodeGeo, nodeMat);
      const angle = (i / nodeCount) * Math.PI * 2;
      const radius = 2.2 + Math.sin(i * 0.7) * 0.4;
      node.userData = {
        angle, radius,
        yOffset: (Math.random() - 0.5) * 1.5,
        speed: 0.024 + Math.random() * 0.015,
        bobSpeed: 1.5 + Math.random() * 1.5,
        bobAmp: 0.1 + Math.random() * 0.15,
      };
      scene.add(node);
      nodes.push(node);
    }

    // ── 4. 240 QUANTUM PARTICLES ────────────────────────────
    const particleCount = 240; 
    const positions = new Float32Array(particleCount * 3);
    const particleSpeeds = new Float32Array(particleCount);
    const particleAngles = new Float32Array(particleCount);
    const particleRadii = new Float32Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      particleAngles[i] = Math.random() * Math.PI * 2;
      particleRadii[i] = 1.0 + Math.random() * 4.0;
      particleSpeeds[i] = (0.003 + Math.random() * 0.008) * (Math.random() > 0.5 ? 1 : -1);
      positions[i * 3 + 1] = (Math.random() - 0.5) * 5;
    }

    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const particleMatBase = new THREE.PointsMaterial({
      color: 0x00e5ff,
      size: 0.06, 
      transparent: true,
      opacity: 0.6,
      sizeAttenuation: true,
    });

    const particles = new THREE.Points(particleGeo, particleMatBase);
    scene.add(particles);

    // ── 5. 6 GLOW ORBS ────────────────────────────────
    const glowGeo = new THREE.SphereGeometry(0.1, 8, 8);
    const glowMat = new THREE.MeshBasicMaterial({ color: 0x00e5ff, transparent: true, opacity: 0.5 });
    const glows = [];
    for (let i = 0; i < 6; i++) {
      const g = new THREE.Mesh(glowGeo, glowMat);
      g.userData.phase = (i / 6) * Math.PI * 2;
      glows.push(g);
      scene.add(g);
    }

    // ── 6. MOUSE PARALLAX ──────────────────────────
    const mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
    const handleMouse = (e) => {
      mouse.targetX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouse.targetY = -(e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('mousemove', handleMouse);

    // ── ANIMATION LOOP ───────────────────────────────────────────────────────
    let frameId;
    const clock = new THREE.Clock();
    let prevT = 0;

    const animate = () => {
      frameId = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();
      const dt = t - prevT;
      prevT = t;

      // Base Mouse Parallax
      mouse.x += (mouse.targetX - mouse.x) * 0.05;
      mouse.y += (mouse.targetY - mouse.y) * 0.05;

      // Lock tracking
      lockGroup.rotation.y = Math.sin(t * 0.4) * 0.12 + (mouse.x * 0.25);
      lockGroup.rotation.x = Math.sin(t * 0.3) * 0.06 - (mouse.y * 0.25);
      lockGroup.position.y = Math.sin(t * 0.6) * 0.08;
      
      // Pulse lights
      coreMat.emissiveIntensity = 2.5 + Math.sin(t * 3) * 1.5;

      // Orbit components
      rings.forEach(r => { 
        r.rotation.y += r.userData.speed; 
        r.rotation.z += r.userData.speed * 0.3; 
      });
      nodes.forEach(node => {
        node.userData.angle += node.userData.speed;
        const { angle, radius, yOffset, bobSpeed, bobAmp } = node.userData;
        node.position.set(Math.cos(angle) * radius, yOffset + Math.sin(t * bobSpeed) * bobAmp, Math.sin(angle) * radius);
        node.rotation.x += 0.02; node.rotation.y += 0.03;
      });

      // Drifting 240 quantum particles
      const pos = particleGeo.attributes.position.array;
      for (let i = 0; i < particleCount; i++) {
        particleAngles[i] += particleSpeeds[i];
        pos[i * 3] = Math.cos(particleAngles[i]) * particleRadii[i];
        pos[i * 3 + 2] = Math.sin(particleAngles[i]) * particleRadii[i];
      }
      particleGeo.attributes.position.needsUpdate = true;

      glows.forEach((g, i) => {
        const phase = g.userData.phase + t * 2.4;
        g.position.set(Math.cos(phase) * 1.05, Math.sin(phase * 0.7) * 0.4, Math.sin(phase) * 1.05);
        const pulse = 0.5 + 0.5 * Math.sin(t * 5 + i);
        g.material.opacity = 0.3 + pulse * 0.4;
        g.scale.setScalar(0.8 + pulse * 0.4);
      });

      // DEFAULT PARALLAX CAMERA
      camera.position.x = mouse.x * 0.2;
      camera.position.y = mouse.y * 0.15;
      camera.position.z = 6;
      camera.lookAt(0, 0, 0);


      // ── CINEMATIC UNLOCK OVERRIDE ──────────────────────────────────────────
      if (isUnlockingRef.current) {
        unlockProgress.current += dt;
        
        // 2-second progression logic curve
        const progress = Math.min(1.0, unlockProgress.current / 2.0); 
        // Smooth easing (Cubic InOut)
        const ease = progress < 0.5 ? 4 * progress * progress * progress : 1 - Math.pow(-2 * progress + 2, 3) / 2;

        // 1. Shackle jumps UP then swings OPEN
        if (ease < 0.4) {
          shackle.position.y = shackleBaseY + (ease / 0.4) * 0.35;
          shackle.rotation.y = 0;
        } else {
          shackle.position.y = shackleBaseY + 0.35; 
          const swingAmount = (ease - 0.4) / 0.6;
          shackle.rotation.y = swingAmount * (Math.PI / 1.5); 
        }

        // 2. Base Lock spins proudly
        lockGroup.rotation.y += ease * 2.5; 

        // 3. Complete lighting overdrive
        cyanLight.intensity = 15 + (ease * 60);
        purpleLight.intensity = 12 + (ease * 40);
        coreMat.emissiveIntensity = 3.5 + (ease * 15);

        // 4. Camera subtle cinematic push
        camera.position.z = 6 - (ease * 1.5); 
        
        // 5. Particles warp jump globally
        for (let i = 0; i < particleCount; i++) {
          particleSpeeds[i] += ease * 0.008 * Math.sign(particleSpeeds[i]); 
        }
      } 
      // ── CINEMATIC LOGOUT REVERSAL ──────────────────────────────────────────
      else if (variant === 'logout' || isLockingRef.current) {
        if (isLockingRef.current) lockProgress.current += dt;
        
        // Count from 0.0 to 1.0 over 2 seconds
        const progress = Math.min(1.0, lockProgress.current / 2.0); 
        
        // Reverse time flow: 1.0 down to 0.0
        const p = 1.0 - progress; 
        
        // Apply identical cubic easing to the reversed time parameter
        const ease = p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;

        if (ease < 0.4) {
          // Drops into place
          shackle.position.y = shackleBaseY + (ease / 0.4) * 0.35;
          shackle.rotation.y = 0;
        } else {
          // Swings shut
          shackle.position.y = shackleBaseY + 0.35; 
          const swingAmount = (ease - 0.4) / 0.6;
          shackle.rotation.y = swingAmount * (Math.PI / 1.5); 
        }

        lockGroup.rotation.y += ease * 2.5; 
        cyanLight.intensity = 15 + (ease * 60);
        purpleLight.intensity = 12 + (ease * 40);
        coreMat.emissiveIntensity = 3.5 + (ease * 15);
        camera.position.z = 6 - (ease * 1.5); 
        
        for (let i = 0; i < particleCount; i++) {
          // Speed decays perfectly back to ambient
          particleSpeeds[i] += ease * 0.008 * Math.sign(particleSpeeds[i]); 
        }
      }

      renderer.render(scene, camera);
    };

    animate();

    // ── RESIZE (Uses Observer to flawlessly track CSS animations) ────────────
    const handleResize = () => {
      if (!mountRef.current) return;
      const w = mountRef.current.clientWidth;
      const h = mountRef.current.clientHeight;
      if (w === 0 || h === 0) return;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    
    const resizeObserver = new ResizeObserver(() => {
      handleResize();
    });
    if (mount) resizeObserver.observe(mount);
    
    handleResize();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('mousemove', handleMouse);
      resizeObserver.disconnect();
      renderer.dispose();
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement);
    };
  }, []);

  return (
    <div
      ref={mountRef}
      style={{ width: '100%', height: '100%', display: 'block', position: 'absolute', top: 0, left: 0 }}
    />
  );
}
